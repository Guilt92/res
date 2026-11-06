//! ACL management (runtime apply + atomic persist).

use super::*;

// ---------------------------------------------------------------------------
// ACL management (runtime apply + atomic persist) and cache control
// ---------------------------------------------------------------------------

/// `source` distinguishes entries loaded from the structured `[[acl.entries]]`
/// config ("config") from those synthesised from the legacy flat
/// `allowed_cidrs`/`denied_cidrs` lists ("legacy") — the dashboard's Source
/// column needs it and cannot be derived client-side.
pub(super) fn acl_entry_json(e: &AclEntry, source: &str) -> Value {
    json!({
        "id": e.id,
        "cidr": e.cidr,
        "action": e.action.as_str(),
        "enabled": e.enabled,
        "source": source,
    })
}

/// Shared guardrails for any ACL mutation that would produce an empty allow
/// list (fail-closed = refuse every query) or a /0 open-resolver allow network.
pub(super) fn acl_guardrails(entries: &[AclEntry], confirm: bool) -> Result<(), ApiError> {
    if confirm {
        return Ok(());
    }
    let any_allow = entries
        .iter()
        .any(|e| e.action == AclAction::Allow && e.enabled);
    if !any_allow {
        return Err(ApiError::NeedsConfirm(
            "every allow entry is disabled or the allow list is empty (fail-closed refuses \
             every DNS query); retry with confirm=true to proceed"
                .into(),
        ));
    }
    let open = entries.iter().any(|e| {
        e.action == AclAction::Allow
            && e.enabled
            && crate::acl::normalize_cidr(&e.cidr)
                .map(|n| n.prefix_len() == 0)
                .unwrap_or(false)
    });
    if open {
        return Err(ApiError::NeedsConfirm(
            "the allow list contains a /0 network, which makes this an open resolver; \
             retry with confirm=true to proceed"
                .into(),
        ));
    }
    Ok(())
}

/// Apply a full entry list to the running config, persist atomically, and
/// record a config event. Callers must already hold the mutation lock, have
/// validated the entries parse, and checked the optimistic generation.
pub(super) async fn apply_acl_entries(
    st: &ApiState,
    entries: Vec<AclEntry>,
    op: &str,
    confirm: bool,
) -> Result<Json<Value>, ApiError> {
    acl_guardrails(&entries, confirm)?;

    let mut next = AppConfig::clone(st.shared.app.load().as_ref());
    next.acl.set_entries(entries.clone());
    if let Err(e) = crate::shared::Shared::validate_config(&mut next) {
        return Err(reject(
            st,
            &format!("{op}_rejected"),
            json!({ "op": op }),
            ApiError::BadRequest(e),
        ));
    }
    let persisted = commit_config(st, next).await?;
    st.shared.record_config_event(
        op,
        json!({
            "entries": entries.len(),
            "persisted": persisted,
            "outcome": "applied",
        }),
    );
    let rt = st.shared.rt.load();
    Ok(Json(json!({
        "status": "ok",
        "entries": entries.iter().map(|e| acl_entry_json(e, "config")).collect::<Vec<_>>(),
        "allowed_count": rt.acl.allowed_count(),
        "denied_count": rt.acl.denied_count(),
        "persisted": persisted,
        "persist_error": Value::Null,
        "generation": st.shared.config_generation(),
    })))
}

/// GET /api/acl — effective entries (with ids) + evaluation counts.
pub(super) async fn get_acl(State(st): State<ApiState>) -> Json<Value> {
    let app = st.shared.app.load();
    let rt = st.shared.rt.load();
    let entries = app.acl.effective_entries();
    let acl_source = if app.acl.entries.is_empty() {
        "legacy"
    } else {
        "config"
    };
    Json(json!({
        "entries": entries
            .iter()
            .map(|e| acl_entry_json(e, acl_source))
            .collect::<Vec<_>>(),
        // Legacy view for older dashboards: synthesised from enabled entries.
        "allowed_cidrs": entries
            .iter()
            .filter(|e| e.action == AclAction::Allow && e.enabled)
            .map(|e| e.cidr.clone())
            .collect::<Vec<_>>(),
        "denied_cidrs": entries
            .iter()
            .filter(|e| e.action == AclAction::Deny && e.enabled)
            .map(|e| e.cidr.clone())
            .collect::<Vec<_>>(),
        "allowed_count": rt.acl.allowed_count(),
        "denied_count": rt.acl.denied_count(),
        "generation": st.shared.config_generation(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AclUpdateRequest {
    /// Preferred shape: full structured entry list (replaces everything).
    #[serde(default)]
    entries: Option<Vec<AclEntry>>,
    /// Legacy shape: flat allow list (used when `entries` is absent).
    #[serde(default)]
    allowed_cidrs: Option<Vec<String>>,
    /// Legacy shape: flat deny list (used when `entries` is absent).
    #[serde(default)]
    denied_cidrs: Option<Vec<String>>,
    /// Optimistic concurrency guard (generation of the read the client edited).
    generation: Option<u64>,
    /// Required when the resulting allow list is empty (fail-closed would
    /// refuse every query) or contains a /0 network (open resolver).
    #[serde(default)]
    confirm: bool,
}

/// PUT /api/acl — validate, apply at runtime, persist atomically. Accepts
/// either the structured `entries` list or the legacy flat CIDR lists.
/// Denies are evaluated before allows (deny wins). Invalid CIDRs, bare-IP
/// normalisation failures, duplicates and allow/deny conflicts are rejected
/// without touching the running rules.
pub(super) async fn put_acl(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<AclPutQuery>,
    Json(req): Json<AclUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "acl_update")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation.or(q.generation), "acl_update")?;

    // Build the entry list from whichever shape the client sent.
    let entries: Vec<AclEntry> = if let Some(entries) = req.entries {
        entries
    } else {
        let allowed = req.allowed_cidrs.unwrap_or_default();
        let denied = req.denied_cidrs.unwrap_or_default();
        let mut out = Vec::with_capacity(allowed.len() + denied.len());
        for s in allowed {
            out.push(AclEntry {
                id: String::new(),
                cidr: s,
                action: AclAction::Allow,
                enabled: true,
            });
        }
        for s in denied {
            out.push(AclEntry {
                id: String::new(),
                cidr: s,
                action: AclAction::Deny,
                enabled: true,
            });
        }
        out
    };

    // Reject invalid CIDRs / duplicates / conflicts before touching anything.
    let mut probe = AclConfig::default();
    probe.set_entries(entries.clone());
    AclRules::parse(&probe).map_err(|e| {
        reject(
            &st,
            "acl_update_rejected",
            json!({ "op": "acl_update" }),
            ApiError::BadRequest(e),
        )
    })?;

    apply_acl_entries(&st, entries, "acl_update", req.confirm).await
}

#[derive(Deserialize)]
pub(super) struct AclPutQuery {
    pub(super) generation: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AclEntryCreate {
    /// CIDR network or bare IPv4/IPv6 address.
    cidr: String,
    /// `"allow"` or `"deny"`.
    action: AclAction,
    /// Defaults to true.
    #[serde(default = "default_true_bool")]
    enabled: bool,
    generation: Option<u64>,
    #[serde(default)]
    confirm: bool,
}

pub(super) fn default_true_bool() -> bool {
    true
}

/// POST /api/acl/entries — append one entry (admin only).
pub(super) async fn create_acl_entry(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<AclEntryCreate>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "acl_entry_create")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation, "acl_entry_create")?;

    let mut entries = st.shared.app.load().acl.effective_entries();
    let new = AclEntry {
        id: String::new(),
        cidr: req.cidr.trim().to_string(),
        action: req.action,
        enabled: req.enabled,
    }
    .with_derived_id();
    // Reject exact duplicates early for a clearer error than the parse path.
    if entries.iter().any(|e| {
        e.action == new.action
            && crate::acl::normalize_cidr(&e.cidr)
                .ok()
                .zip(crate::acl::normalize_cidr(&new.cidr).ok())
                .map(|(a, b)| a == b)
                .unwrap_or(false)
    }) {
        return Err(ApiError::Conflict(format!(
            "duplicate ACL entry: {} {}",
            new.action.as_str(),
            new.cidr
        )));
    }
    entries.push(new);
    apply_acl_entries(&st, entries, "acl_entry_create", req.confirm).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AclEntryPatch {
    /// New CIDR (bare IP or network).
    #[serde(default)]
    cidr: Option<String>,
    #[serde(default)]
    action: Option<AclAction>,
    #[serde(default)]
    enabled: Option<bool>,
    generation: Option<u64>,
    #[serde(default)]
    confirm: bool,
}

/// PATCH /api/acl/entries/{id} — update one entry in place (admin only).
pub(super) async fn patch_acl_entry(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<AclEntryPatch>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "acl_entry_patch")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation, "acl_entry_patch")?;

    let mut entries = st.shared.app.load().acl.effective_entries();
    let pos = entries
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("ACL entry '{id}' not found")))?;

    if let Some(cidr) = &req.cidr {
        entries[pos].cidr = cidr.trim().to_string();
    }
    if let Some(action) = req.action {
        entries[pos].action = action;
    }
    if let Some(enabled) = req.enabled {
        entries[pos].enabled = enabled;
    }
    // Changing cidr/action invalidates a content-derived id; re-derive so the
    // id stays a stable function of the entry's meaning.
    if req.cidr.is_some() || req.action.is_some() {
        entries[pos].id = AclEntry::derive_id(entries[pos].action, &entries[pos].cidr);
    }
    apply_acl_entries(&st, entries, "acl_entry_patch", req.confirm).await
}

#[derive(Deserialize)]
pub(super) struct AclEntryDeleteQuery {
    generation: Option<u64>,
    #[serde(default)]
    confirm: bool,
}

/// DELETE /api/acl/entries/{id} — remove one entry (admin only).
pub(super) async fn delete_acl_entry(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<AclEntryDeleteQuery>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "acl_entry_delete")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, q.generation, "acl_entry_delete")?;

    let mut entries = st.shared.app.load().acl.effective_entries();
    let pos = entries
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("ACL entry '{id}' not found")))?;
    entries.remove(pos);
    apply_acl_entries(&st, entries, "acl_entry_delete", q.confirm).await
}
