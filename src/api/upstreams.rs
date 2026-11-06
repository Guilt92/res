//! Upstream CRUD, listing, probing and per-upstream health events.

use super::*;

// ---------------------------------------------------------------------------
// Upstream CRUD
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUpstreamRequest {
    pub name: String,
    pub address: String,
    pub port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub enabled: Option<bool>,
    pub priority: Option<u32>,
    pub weight: Option<u32>,
    pub timeout_ms: Option<u64>,
    /// Per-upstream health probe interval override (ms).
    pub probe_interval_ms: Option<u64>,
    /// Per-upstream health probe timeout override (ms).
    pub probe_timeout_ms: Option<u64>,
    /// Per-upstream probe list override (replaces `[health].probes`).
    pub probes: Option<Vec<crate::config::HealthProbe>>,
    /// Per-upstream expected rcode for health probes (`UpstreamConfig::expect_rcode`).
    pub expect_rcode: Option<String>,
    /// SNI/certificate name for `protocol = "tls"`.
    pub tls_server_name: Option<String>,
    /// Optional PEM CA bundle for `protocol = "tls"`.
    pub tls_ca_file: Option<std::path::PathBuf>,
    /// Accepted and ignored on create (the dashboard sends `confirm` on every
    /// write; only updates/deletes need it). Typed here because
    /// `deny_unknown_fields` would otherwise reject the panel's payload with
    /// a 422 — the "Add upstream" button was broken by exactly that.
    #[allow(dead_code)] // deserialized for compatibility, intentionally unused
    pub confirm: Option<bool>,
    /// Optional optimistic-concurrency guard: reject if the active
    /// configuration generation no longer matches.
    pub generation: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateUpstreamRequest {
    pub name: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub enabled: Option<bool>,
    pub priority: Option<u32>,
    pub weight: Option<u32>,
    pub timeout_ms: Option<u64>,
    /// Explicitly clear the timeout override.
    pub clear_timeout: Option<bool>,
    /// Per-upstream health probe interval override (ms).
    pub probe_interval_ms: Option<u64>,
    /// Per-upstream health probe timeout override (ms).
    pub probe_timeout_ms: Option<u64>,
    /// Explicitly clear the probe interval override (back to inheriting
    /// `[health].interval`). Independent of `clear_probes`: wiping the probe
    /// *list* must not silently delete the cadence overrides.
    pub clear_probe_interval_ms: Option<bool>,
    /// Explicitly clear the probe timeout override (back to inheriting
    /// `[health].timeout`).
    pub clear_probe_timeout_ms: Option<bool>,
    /// Per-upstream probe list override (replaces `[health].probes`).
    pub probes: Option<Vec<crate::config::HealthProbe>>,
    /// Per-upstream expected rcode for health probes; validated against the
    /// known rcode set by `UpstreamConfig::validate`.
    pub expect_rcode: Option<String>,
    /// Explicitly clear the `expect_rcode` override.
    pub clear_expect_rcode: Option<bool>,
    /// SNI/certificate name for `protocol = "tls"`.
    pub tls_server_name: Option<String>,
    /// Optional PEM CA bundle for `protocol = "tls"`.
    pub tls_ca_file: Option<std::path::PathBuf>,
    /// Explicitly clear the TLS server name / CA bundle.
    pub clear_tls: Option<bool>,
    /// Explicitly clear the per-upstream probe overrides.
    pub clear_probes: Option<bool>,
    /// Required when the update would disable the last enabled upstream.
    pub confirm: Option<bool>,
    /// Optional optimistic-concurrency guard (see `CreateUpstreamRequest`).
    pub generation: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteUpstreamQuery {
    pub confirm: Option<bool>,
    pub generation: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportConfigQuery {
    pub confirm: Option<bool>,
    pub generation: Option<u64>,
}

pub(super) fn parse_address(s: &str) -> Result<IpAddr, ApiError> {
    s.trim()
        .parse()
        .map_err(|e| ApiError::BadRequest(format!("invalid address '{s}': {e}")))
}

pub(super) async fn list_upstreams(State(st): State<ApiState>) -> Json<Value> {
    use crate::upstream::HealthStatus;

    let sel = st.shared.rt.load().selection.clone();
    let latency_ref = sel.latency_reference_ms;
    let min_probe_samples = sel.min_probe_samples;
    let rows: Vec<crate::upstream::UpstreamStats> = st
        .shared
        .registry
        .snapshot()
        .iter()
        .map(|u| u.stats_with_latency_ref(latency_ref, min_probe_samples))
        .collect();

    // Selection semantics (mirrors `selection.rs`): an UNHEALTHY upstream is
    // scored 0 while any upstream is HEALTHY, so it is *kept* as a fallback
    // but not used. RECOVERING is usable (scored between healthy and
    // degraded). With `degraded_policy = "last_resort"`, DEGRADED behaves like
    // UNHEALTHY while any HEALTHY/RECOVERING upstream exists.
    let any_up = rows
        .iter()
        .any(|r| r.enabled && matches!(r.health, HealthStatus::Healthy | HealthStatus::Recovering));
    let degraded_last_resort =
        st.shared.rt.load().selection.degraded_policy == crate::config::DegradedPolicy::LastResort;
    let mut eligible = Vec::new();
    let mut in_use = Vec::new();
    let mut idle = Vec::new();
    let mut avoided = Vec::new();
    let mut disabled = Vec::new();
    let (mut up, mut degraded, mut recovering, mut down) = (0usize, 0usize, 0usize, 0usize);
    let mut sum_qps = 0.0f64;

    // First pass: classify, then rank eligible upstreams by composite score
    // (descending) so operators can see why a given upstream wins or loses.
    let classified: Vec<(Value, bool, f64, String)> = rows
        .iter()
        .map(|r| {
            let mut v = serde_json::to_value(r).expect("serializable");
            if !r.enabled {
                disabled.push(r.name.clone());
                v["eligible"] = Value::Bool(false);
                return (v, false, 0.0, "disabled".into());
            }
            match r.health {
                HealthStatus::Healthy => up += 1,
                HealthStatus::Degraded => degraded += 1,
                HealthStatus::Recovering => recovering += 1,
                HealthStatus::Unhealthy => down += 1,
            }
            let is_eligible =
                crate::selection::candidate_eligible(r.health, any_up, degraded_last_resort);
            v["eligible"] = Value::Bool(is_eligible);
            sum_qps += r.qps;
            let reason = match (r.health, is_eligible) {
                (HealthStatus::Healthy, true) => "healthy",
                (HealthStatus::Recovering, true) => "recovering",
                (HealthStatus::Degraded, true) => "degraded_usable",
                (HealthStatus::Degraded, false) => "degraded_last_resort",
                (HealthStatus::Unhealthy, _) => "unhealthy",
                _ => "not_eligible",
            };
            (v, is_eligible, r.score.score, reason.into())
        })
        .collect();

    // Rank eligible by score descending (stable: higher score first, ties
    // broken by lower upstream id for determinism).
    let mut order: Vec<usize> = classified
        .iter()
        .enumerate()
        .filter(|(_, (_, ok, _, _))| *ok)
        .map(|(i, _)| i)
        .collect();
    order.sort_by(|&a, &b| {
        classified[b]
            .2
            .partial_cmp(&classified[a].2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                let id_a = classified[a].0["id"].as_i64().unwrap_or(i64::MAX);
                let id_b = classified[b].0["id"].as_i64().unwrap_or(i64::MAX);
                id_a.cmp(&id_b)
            })
    });
    let mut ranks: HashMap<i64, u32> = HashMap::new();
    for (rank, &idx) in order.iter().enumerate() {
        let id = classified[idx].0["id"].as_i64().unwrap_or(0);
        ranks.insert(id, rank as u32 + 1);
    }

    let upstreams: Vec<Value> = classified
        .into_iter()
        .map(|(mut v, is_eligible, score, reason)| {
            let id = v["id"].as_i64().unwrap_or(0);
            // Keep the serialized `score` breakdown (factors + composite):
            // the dashboard renders the factors in a tooltip. `score_value`
            // is the same composite as a plain number for scripted clients.
            v["score_value"] = json!(score);
            v["rank"] = ranks.get(&id).map_or(Value::Null, |r| json!(r));
            v["reason"] = Value::String(reason);
            if is_eligible {
                eligible.push(v["name"].as_str().unwrap_or("").to_string());
                let in_use_now = v["in_use"].as_bool().unwrap_or(false);
                if in_use_now {
                    in_use.push(v["name"].as_str().unwrap_or("").to_string());
                } else {
                    idle.push(v["name"].as_str().unwrap_or("").to_string());
                }
            } else if v["enabled"].as_bool().unwrap_or(true) {
                avoided.push(v["name"].as_str().unwrap_or("").to_string());
            }
            v
        })
        .collect();
    let usable = up + degraded + recovering;
    let emergency = !rows.is_empty() && eligible.is_empty();

    Json(json!({
        "upstreams": upstreams,
        "generation": st.shared.config_generation(),
        "state": {
            "total": rows.len(),
            // "up"/"down" are legacy aliases for healthy/unhealthy counts;
            // the canonical per-state names are healthy/degraded/recovering/
            // unhealthy (also present on each upstream's `health` field).
            "up": up,
            "healthy": up,
            "degraded": degraded,
            "recovering": recovering,
            "usable": usable,
            "unhealthy": down,
            "down": down,
            "disabled": disabled.len(),
            "eligible": eligible,
            "in_use": in_use,
            "idle": idle,
            "avoided": avoided,
            "disabled_names": disabled,
            "total_qps": round2(sum_qps),
            // Canonical emergency: no configured upstream can serve. A
            // disabled-but-healthy upstream must not mask this.
            "emergency": emergency,
        },
    }))
}

pub(super) async fn get_upstream(
    State(st): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let sel = st.shared.rt.load().selection.clone();
    st.shared
        .registry
        .get(id)
        .map(|u| {
            Json(json!({
                "upstream": serde_json::to_value(
                    u.stats_with_latency_ref(sel.latency_reference_ms, sel.min_probe_samples)
                ).unwrap()
            }))
        })
        .ok_or_else(|| ApiError::NotFound(format!("upstream {id} not found")))
}

pub(super) async fn create_upstream(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<CreateUpstreamRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    require_admin(&st, &headers, "create")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation, "create")?;
    let current: AppConfig = (**st.shared.app.load()).clone();

    let name_hint: String = req.name.trim().chars().take(64).collect();
    let mut candidate = UpstreamConfig {
        id: 0,
        name: req.name.trim().to_string(),
        address: parse_address(&req.address)
            .map_err(|e| reject(&st, "create_rejected", json!({ "name": name_hint }), e))?,
        port: req.port.unwrap_or(53),
        protocol: req.protocol.unwrap_or(Protocol::Udp),
        enabled: req.enabled.unwrap_or(true),
        priority: req.priority.unwrap_or(1),
        weight: req.weight.unwrap_or(1),
        timeout_ms: req.timeout_ms,
        probe_interval_ms: req.probe_interval_ms,
        probe_timeout_ms: req.probe_timeout_ms,
        probes: req.probes.clone(),
        expect_rcode: req.expect_rcode.clone(),
        tls_server_name: req.tls_server_name.clone(),
        tls_ca_file: req.tls_ca_file.clone(),
    };
    candidate.validate().map_err(|e| {
        reject(
            &st,
            "create_rejected",
            json!({ "name": candidate.name }),
            ApiError::BadRequest(e),
        )
    })?;
    if current.upstreams.iter().any(|u| u.name == candidate.name) {
        return Err(reject(
            &st,
            "create_rejected",
            json!({ "name": candidate.name }),
            ApiError::Conflict(format!("upstream name '{}' already exists", candidate.name)),
        ));
    }

    let mut list = current.upstreams.clone();
    let next_id = list.iter().map(|u| u.id).max().unwrap_or(0).max(0) + 1;
    candidate.id = next_id;
    list.push(candidate.clone());

    let mut next = current.with_upstreams(list).map_err(|e| {
        reject(
            &st,
            "create_rejected",
            json!({ "name": candidate.name }),
            ApiError::BadRequest(e),
        )
    })?;
    if let Err(e) = crate::shared::Shared::validate_config(&mut next) {
        return Err(reject(
            &st,
            "create_rejected",
            json!({ "name": candidate.name }),
            ApiError::BadRequest(e),
        ));
    }
    let persisted = commit_config(&st, next).await?;
    st.shared.record_config_event(
        "create",
        json!({
            "id": next_id,
            "name": candidate.name,
            "persisted": persisted,
            "outcome": "applied",
        }),
    );

    let sel = st.shared.rt.load().selection.clone();
    let stats = st
        .shared
        .registry
        .get(next_id)
        .map(|u| {
            serde_json::to_value(
                u.stats_with_latency_ref(sel.latency_reference_ms, sel.min_probe_samples),
            )
            .unwrap()
        })
        .unwrap_or(Value::Null);
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "upstream": stats,
            "persisted": persisted,
            "persist_error": Value::Null,
            "generation": st.shared.config_generation(),
        })),
    ))
}

pub(super) async fn patch_upstream(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<UpdateUpstreamRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "update")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation, "update")?;
    let current: AppConfig = (**st.shared.app.load()).clone();

    let existing = current
        .upstreams
        .iter()
        .find(|u| u.id == id)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("upstream {id} not found")))?;

    let mut updated = existing.clone();
    if let Some(name) = &req.name {
        updated.name = name.trim().to_string();
    }
    if let Some(addr) = &req.address {
        updated.address = parse_address(addr)?;
    }
    if let Some(port) = req.port {
        updated.port = port;
    }
    if let Some(proto) = req.protocol {
        updated.protocol = proto;
    }
    if let Some(enabled) = req.enabled {
        updated.enabled = enabled;
    }
    if let Some(priority) = req.priority {
        updated.priority = priority;
    }
    if let Some(weight) = req.weight {
        updated.weight = weight;
    }
    if Some(true) == req.clear_timeout {
        updated.timeout_ms = None;
    } else if let Some(t) = req.timeout_ms {
        updated.timeout_ms = Some(t);
    }
    if Some(true) == req.clear_expect_rcode {
        updated.expect_rcode = None;
    } else if let Some(rc) = &req.expect_rcode {
        updated.expect_rcode = Some(rc.clone());
    }
    if Some(true) == req.clear_tls {
        updated.tls_server_name = None;
        updated.tls_ca_file = None;
    } else {
        if let Some(name) = &req.tls_server_name {
            updated.tls_server_name = if name.trim().is_empty() {
                None
            } else {
                Some(name.clone())
            };
        }
        if let Some(path) = &req.tls_ca_file {
            updated.tls_ca_file = Some(path.clone());
        }
    }
    if Some(true) == req.clear_probes {
        updated.probes = None;
    } else if let Some(probes) = &req.probes {
        updated.probes = Some(probes.clone());
    }
    if Some(true) == req.clear_probe_interval_ms {
        updated.probe_interval_ms = None;
    } else if let Some(t) = req.probe_interval_ms {
        updated.probe_interval_ms = Some(t);
    }
    if Some(true) == req.clear_probe_timeout_ms {
        updated.probe_timeout_ms = None;
    } else if let Some(t) = req.probe_timeout_ms {
        updated.probe_timeout_ms = Some(t);
    }
    updated.validate().map_err(|e| {
        reject(
            &st,
            "update_rejected",
            json!({ "id": id, "name": updated.name }),
            ApiError::BadRequest(e),
        )
    })?;
    if current
        .upstreams
        .iter()
        .any(|u| u.id != id && u.name == updated.name)
    {
        return Err(reject(
            &st,
            "update_rejected",
            json!({ "id": id, "name": updated.name }),
            ApiError::Conflict(format!("upstream name '{}' already exists", updated.name)),
        ));
    }

    let list: Vec<UpstreamConfig> = current
        .upstreams
        .iter()
        .map(|u| {
            if u.id == id {
                updated.clone()
            } else {
                u.clone()
            }
        })
        .collect();
    check_last_usable(
        &st,
        &list,
        req.confirm.unwrap_or(false),
        "update",
        &updated.name,
    )?;
    let mut next = current.with_upstreams(list).map_err(|e| {
        reject(
            &st,
            "update_rejected",
            json!({ "id": id, "name": updated.name }),
            ApiError::BadRequest(e),
        )
    })?;
    if let Err(e) = crate::shared::Shared::validate_config(&mut next) {
        return Err(reject(
            &st,
            "update_rejected",
            json!({ "id": id, "name": updated.name }),
            ApiError::BadRequest(e),
        ));
    }
    let persisted = commit_config(&st, next).await?;
    st.shared.record_config_event(
        "update",
        json!({
            "id": id,
            "name": updated.name,
            "persisted": persisted,
            "outcome": "applied",
        }),
    );

    let sel = st.shared.rt.load().selection.clone();
    let stats = st
        .shared
        .registry
        .get(id)
        .map(|u| {
            serde_json::to_value(
                u.stats_with_latency_ref(sel.latency_reference_ms, sel.min_probe_samples),
            )
            .unwrap()
        })
        .unwrap_or(Value::Null);
    Ok(Json(json!({
        "upstream": stats,
        "persisted": persisted,
        "persist_error": Value::Null,
        "generation": st.shared.config_generation(),
    })))
}

pub(super) async fn delete_upstream(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<DeleteUpstreamQuery>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "delete")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, q.generation, "delete")?;
    let current: AppConfig = (**st.shared.app.load()).clone();

    let existing = current
        .upstreams
        .iter()
        .find(|u| u.id == id)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("upstream {id} not found")))?;

    let list: Vec<UpstreamConfig> = current
        .upstreams
        .iter()
        .filter(|u| u.id != id)
        .cloned()
        .collect();
    check_last_usable(
        &st,
        &list,
        q.confirm.unwrap_or(false),
        "delete",
        &existing.name,
    )?;
    let mut next = current.with_upstreams(list).map_err(|e| {
        reject(
            &st,
            "delete_rejected",
            json!({ "id": id, "name": existing.name }),
            ApiError::BadRequest(e),
        )
    })?;
    if let Err(e) = crate::shared::Shared::validate_config(&mut next) {
        return Err(reject(
            &st,
            "delete_rejected",
            json!({ "id": id, "name": existing.name }),
            ApiError::BadRequest(e),
        ));
    }
    let persisted = commit_config(&st, next).await?;
    st.shared.record_config_event(
        "delete",
        json!({
            "id": id,
            "name": existing.name,
            "persisted": persisted,
            "outcome": "applied",
        }),
    );

    Ok(Json(json!({
        "deleted": id,
        "persisted": persisted,
        "persist_error": Value::Null,
        "generation": st.shared.config_generation(),
    })))
}

pub(super) async fn test_upstream(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "test")?;
    let runtime = st
        .shared
        .registry
        .get(id)
        .ok_or_else(|| ApiError::NotFound(format!("upstream {id} not found")))?;
    let cfg = runtime.config();
    // Build from the live configuration so a proxy change applies to the
    // operator-triggered probe immediately.
    let forwarder = Forwarder::from_shared(&st.shared);
    let result = probe_once(&st.shared, &forwarder, &runtime).await;
    Ok(Json(json!({
        "upstream": cfg.name,
        "address": cfg.address.to_string(),
        "port": cfg.port,
        "protocol": cfg.protocol.to_string(),
        "result": result,
        "health": runtime.health_status(),
    })))
}

/// Recent recorded events for one upstream (health transitions + probes).
pub(super) async fn upstream_events(
    State(st): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    if st.shared.registry.get(id).is_none() {
        return Err(ApiError::NotFound(format!("upstream {id} not found")));
    }
    let events = st.shared.events.health.recent_for_upstream(id, 50);
    Ok(Json(json!({ "events": events })))
}
