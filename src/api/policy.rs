//! Health-check and upstream-selection policy configuration.

use super::*;

// ---------------------------------------------------------------------------
// Health-check and selection policy configuration (read + write)
// ---------------------------------------------------------------------------

/// GET `/api/health/config`: the full `[health]` section as the dashboard
/// edits it (the liveness probe stays at the open `/api/health` route).
pub(super) async fn get_health_config(State(st): State<ApiState>) -> Json<Value> {
    let app = st.shared.app.load();
    Json(json!({
        "health": app.health,
        "generation": st.shared.config_generation(),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HealthConfigUpdateRequest {
    enabled: Option<bool>,
    interval_ms: Option<u64>,
    timeout_ms: Option<u64>,
    failure_threshold: Option<u32>,
    recovery_threshold: Option<u32>,
    min_successes: Option<usize>,
    tcp_probes: Option<bool>,
    probes: Option<Vec<crate::config::HealthProbe>>,
    dwell_ms: Option<u64>,
    generation: Option<u64>,
}

pub(super) async fn put_health_config(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<AclPutQuery>,
    Json(req): Json<HealthConfigUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "health_update")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation.or(q.generation), "health_update")?;

    let mut next = AppConfig::clone(st.shared.app.load().as_ref());
    let probes_updated = req.probes.is_some();
    if let Some(v) = req.enabled {
        next.health.enabled = v;
    }
    if let Some(v) = req.interval_ms {
        next.health.interval_ms = v;
    }
    if let Some(v) = req.timeout_ms {
        next.health.timeout_ms = v;
    }
    if let Some(v) = req.failure_threshold {
        next.health.failure_threshold = v;
    }
    if let Some(v) = req.recovery_threshold {
        next.health.recovery_threshold = v;
    }
    if let Some(v) = req.min_successes {
        next.health.min_successes = v;
    }
    if let Some(v) = req.tcp_probes {
        next.health.tcp_probes = v;
    }
    if let Some(v) = req.probes {
        next.health.probes = v;
    }
    if let Some(v) = req.dwell_ms {
        next.health.dwell_ms = v;
    }
    if let Err(e) = crate::shared::Shared::validate_config(&mut next) {
        return Err(reject(
            &st,
            "health_update_rejected",
            json!({ "op": "health_update" }),
            ApiError::BadRequest(e),
        ));
    }
    let persisted = commit_config(&st, next).await?;
    st.shared.record_config_event(
        "health_update",
        json!({
            "enabled": req.enabled,
            "interval_ms": req.interval_ms,
            "timeout_ms": req.timeout_ms,
            "probes": probes_updated,
            "persisted": persisted,
            "outcome": "applied",
        }),
    );
    Ok(Json(json!({
        "status": "ok",
        "health": st.shared.app.load().health,
        "persisted": persisted,
        "persist_error": Value::Null,
        "generation": st.shared.config_generation(),
    })))
}

pub(super) async fn get_selection(State(st): State<ApiState>) -> Json<Value> {
    let app = st.shared.app.load();
    Json(json!({
        "selection": app.selection,
        "generation": st.shared.config_generation(),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SelectionConfigUpdateRequest {
    strategy: Option<crate::config::SelectionStrategy>,
    latency_reference_ms: Option<f64>,
    tier_policy: Option<crate::config::TierPolicy>,
    lower_tier_share: Option<f64>,
    degraded_policy: Option<crate::config::DegradedPolicy>,
    min_probe_samples: Option<u32>,
    generation: Option<u64>,
}

pub(super) async fn put_selection(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<AclPutQuery>,
    Json(req): Json<SelectionConfigUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "selection_update")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation.or(q.generation), "selection_update")?;

    let mut next = AppConfig::clone(st.shared.app.load().as_ref());
    if let Some(v) = req.strategy {
        next.selection.strategy = v;
    }
    if let Some(v) = req.latency_reference_ms {
        next.selection.latency_reference_ms = v;
    }
    if let Some(v) = req.tier_policy {
        next.selection.tier_policy = v;
    }
    if let Some(v) = req.lower_tier_share {
        next.selection.lower_tier_share = v;
    }
    if let Some(v) = req.degraded_policy {
        next.selection.degraded_policy = v;
    }
    if let Some(v) = req.min_probe_samples {
        next.selection.min_probe_samples = v;
    }
    if let Err(e) = crate::shared::Shared::validate_config(&mut next) {
        return Err(reject(
            &st,
            "selection_update_rejected",
            json!({ "op": "selection_update" }),
            ApiError::BadRequest(e),
        ));
    }
    let persisted = commit_config(&st, next).await?;
    st.shared.record_config_event(
        "selection_update",
        json!({
            "strategy": req.strategy,
            "latency_reference_ms": req.latency_reference_ms,
            "tier_policy": req.tier_policy,
            "lower_tier_share": req.lower_tier_share,
            "degraded_policy": req.degraded_policy,
            "min_probe_samples": req.min_probe_samples,
            "persisted": persisted,
            "outcome": "applied",
        }),
    );
    let rt = st.shared.rt.load();
    Ok(Json(json!({
        "status": "ok",
        "selection": rt.selection,
        "persisted": persisted,
        "persist_error": Value::Null,
        "generation": st.shared.config_generation(),
    })))
}
