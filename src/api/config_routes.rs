//! Configuration export / import / rollback and the audit-event feeds.

use super::*;

// ---------------------------------------------------------------------------
// Configuration export / import / events
// ---------------------------------------------------------------------------

pub(super) async fn export_config(State(st): State<ApiState>) -> Result<Json<Value>, ApiError> {
    let app = st.shared.app.load();
    // Secrets (proxy password, bearer token) are never exported, for any
    // role. Importing the export back preserves the live values.
    let toml_text = app.to_toml_redacted().map_err(ApiError::Internal)?;
    Ok(Json(json!({
        "toml": toml_text,
        "path": st.shared.config_path.get().map(|p| p.display().to_string()),
        "source": st.shared.config_state().source,
        "error": st.shared.config_state().error,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImportConfigRequest {
    toml: String,
    /// Also write the imported configuration to disk (default true).
    #[serde(default = "default_true")]
    persist: bool,
    /// Secrets to remove explicitly (`"proxy_password"`, `"api_token"`).
    /// Exports never contain secrets, so an import that omits one keeps the
    /// running value unless it is listed here; a non-empty value in the
    /// imported TOML replaces it.
    #[serde(default)]
    clear_secrets: Vec<crate::config::SecretField>,
}

pub(super) fn default_true() -> bool {
    true
}

pub(super) async fn import_config(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<ImportConfigQuery>,
    Json(req): Json<ImportConfigRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "import")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, q.generation, "import")?;

    // Parse + validate BEFORE touching runtime state: an invalid import must
    // leave the running configuration completely unchanged.
    let mut next = AppConfig::parse(&req.toml).map_err(|e| {
        reject(
            &st,
            "import_rejected",
            json!({ "op": "import" }),
            ApiError::BadRequest(e),
        )
    })?;
    if let Err(e) = crate::shared::Shared::validate_config(&mut next) {
        return Err(reject(
            &st,
            "import_rejected",
            json!({ "op": "import" }),
            ApiError::BadRequest(e),
        ));
    }

    let secrets_preserved = {
        let current = st.shared.app.load();
        next.merge_import_secrets(current.as_ref(), &req.clear_secrets)
    };
    if let Err(e) = crate::shared::Shared::validate_config(&mut next) {
        return Err(reject(
            &st,
            "import_rejected",
            json!({ "op": "import" }),
            ApiError::BadRequest(e),
        ));
    }

    check_last_usable(
        &st,
        &next.upstreams,
        q.confirm.unwrap_or(false),
        "import",
        "(all)",
    )?;

    let persisted = if req.persist {
        commit_config(&st, next).await?
    } else {
        st.shared.replace_config(next).map_err(|e| {
            reject(
                &st,
                "import_rejected",
                json!({ "op": "import" }),
                ApiError::Internal(e),
            )
        })?;
        false
    };

    st.shared.record_config_event(
        "import",
        json!({
            "upstreams": st.shared.app.load().upstreams.len(),
            "persisted": persisted,
            "secrets_preserved": secrets_preserved,
            "outcome": "applied",
        }),
    );

    Ok(Json(json!({
        "status": "ok",
        "persisted": persisted,
        "persist_error": Value::Null,
        "secrets_preserved": secrets_preserved,
        "upstreams": st.shared.app.load().upstreams.len(),
        "generation": st.shared.config_generation(),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RollbackConfigQuery {
    generation: Option<u64>,
    #[serde(default)]
    confirm: bool,
}

/// POST /api/config/rollback — restore the configuration from the
/// `<file>.backup` written by the previous successful persist. Applies at
/// runtime and re-persists the restored content as the primary file (so the
/// backup becomes the pre-rollback configuration, enabling a double-rollback).
pub(super) async fn rollback_config(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<RollbackConfigQuery>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "rollback")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, q.generation, "rollback")?;

    let Some(path) = st.shared.config_path.get().cloned() else {
        return Err(ApiError::BadRequest(
            "no configuration file is set; rollback requires a persisted config path".into(),
        ));
    };
    let backup = AppConfig::backup_path(&path);
    if !backup.exists() {
        return Err(ApiError::NotFound(format!(
            "no backup file at {}",
            backup.display()
        )));
    }

    // Parse + validate BEFORE touching runtime state. The restored config is
    // persisted first, so a failed write leaves the active and on-disk
    // configuration untouched.
    let mut next = AppConfig::load(&backup).map_err(|e| {
        reject(
            &st,
            "rollback_rejected",
            json!({ "op": "rollback", "backup": backup.display().to_string() }),
            ApiError::BadRequest(format!("backup is invalid: {e}")),
        )
    })?;
    if let Err(e) = crate::shared::Shared::validate_config(&mut next) {
        return Err(reject(
            &st,
            "rollback_rejected",
            json!({ "op": "rollback" }),
            ApiError::BadRequest(e),
        ));
    }

    check_last_usable(&st, &next.upstreams, q.confirm, "rollback", "(backup)")?;

    let persisted = commit_config(&st, next).await?;

    st.shared.record_config_event(
        "rollback",
        json!({
            "backup": backup.display().to_string(),
            "upstreams": st.shared.app.load().upstreams.len(),
            "persisted": persisted,
            "outcome": "applied",
        }),
    );

    Ok(Json(json!({
        "status": "ok",
        "backup": backup.display().to_string(),
        "persisted": persisted,
        "persist_error": Value::Null,
        "upstreams": st.shared.app.load().upstreams.len(),
        "generation": st.shared.config_generation(),
    })))
}

#[derive(Deserialize)]
pub(super) struct EventsQuery {
    /// `config`, `health`, `failover` or `system` (default: all merged).
    kind: Option<String>,
    limit: Option<usize>,
}

pub(super) async fn config_events(State(st): State<ApiState>) -> Json<Value> {
    let events = st.shared.events.config.recent(100);
    Json(json!({ "events": events }))
}

pub(super) async fn all_events(
    State(st): State<ApiState>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 256);
    let mut events: Vec<Event> = match q.kind.as_deref() {
        Some("config") => st.shared.events.config.recent(limit),
        Some("health") => st.shared.events.health.recent(limit),
        Some("failover") => st.shared.events.failover.recent(limit),
        Some("system") => st.shared.events.system.recent(limit),
        Some(other) => {
            return Err(ApiError::BadRequest(format!(
                "unknown kind '{other}' (expected config|health|failover|system)"
            )))
        }
        None => merge_event_shares(
            [
                st.shared.events.config.recent(limit),
                st.shared.events.health.recent(limit),
                st.shared.events.failover.recent(limit),
                st.shared.events.system.recent(limit),
            ],
            limit,
        ),
    };
    events.sort_by_key(|e| std::cmp::Reverse(e.ts_ms));
    Ok(Json(json!({ "events": events })))
}

/// Merge per-kind event pools (each newest-first) into one newest-first
/// window of at most `limit` events.
///
/// Every kind first gets `ceil(limit / kinds)` slots (minimum 4 while the
/// limit allows), so a flood in one ring cannot evict the other kinds; the
/// remaining slots go to whatever is newest across all pools.
pub(super) fn merge_event_shares(mut pools: [Vec<Event>; 4], limit: usize) -> Vec<Event> {
    let kinds = pools.len() as f64;
    let share = ((limit as f64 / kinds).ceil() as usize).max(4.min(limit));
    let mut out: Vec<Event> = Vec::with_capacity(limit);
    for pool in &mut pools {
        let take = share.min(pool.len()).min(limit.saturating_sub(out.len()));
        for _ in 0..take {
            if pool.is_empty() {
                break;
            }
            out.push(pool.remove(0));
        }
        if out.len() >= limit {
            break;
        }
    }
    // Top up with the globally newest leftovers.
    while out.len() < limit {
        let mut best: Option<usize> = None;
        for (i, pool) in pools.iter().enumerate() {
            if let Some(e) = pool.first() {
                if best.is_none()
                    || pools[best.unwrap()]
                        .first()
                        .is_some_and(|b| e.ts_ms > b.ts_ms)
                {
                    best = Some(i);
                }
            }
        }
        match best {
            Some(i) => out.push(pools[i].remove(0)),
            None => break,
        }
    }
    out.truncate(limit);
    out.sort_by_key(|e| std::cmp::Reverse(e.ts_ms));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_import_request_is_rejected_by_serde() {
        let res: Result<ImportConfigRequest, _> = serde_json::from_str(r#"{"bogus": 1}"#);
        assert!(res.is_err());
    }

    #[test]
    fn merged_events_keep_every_kind_during_a_flood() {
        // 100 failovers, all newer than everything else: the merge must still
        // reserve room for the older config / health / system events.
        let mk = |action: &str, ts_ms: u64| {
            let mut e = Event::config(action, json!({}));
            e.ts_ms = ts_ms;
            e
        };
        let config = vec![mk("startup", 1_000), mk("apply", 2_000)];
        let health = vec![mk("transition", 3_000), mk("transition", 4_000)];
        let failover: Vec<Event> = (0..100).map(|i| mk("retry", 10_000 + i)).collect();
        let system = vec![mk("rate_limited", 5_000)];

        let out = merge_event_shares([config, health, failover, system], 20);
        assert!(out.len() <= 20);
        assert!(out.iter().any(|e| e.action == "startup"), "config kept");
        assert!(out.iter().any(|e| e.action == "transition"), "health kept");
        assert!(
            out.iter().any(|e| e.action == "rate_limited"),
            "system kept"
        );
        assert!(out.iter().any(|e| e.action == "retry"), "failovers kept");
        // Newest first.
        assert!(out.windows(2).all(|w| w[0].ts_ms >= w[1].ts_ms));
        // A small limit must not panic or go negative on the share math.
        let out = merge_event_shares([vec![mk("startup", 1)], vec![], vec![], vec![]], 1);
        assert_eq!(out.len(), 1);
    }
}
