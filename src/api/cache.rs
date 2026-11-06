//! Response-cache control and hot-reloadable cache settings.

use super::*;

/// POST /api/cache/clear — drop every cache entry immediately (admin only).
pub(super) async fn clear_cache(
    State(st): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "cache_clear")?;
    let before = st.shared.cache.len();
    let mem = st.shared.cache.memory_bytes();
    st.shared.cache.clear();
    st.shared.metrics.cache_entries.set(0);
    st.shared.metrics.cache_memory_bytes.set(0);
    st.shared.metrics.cache_clears_total.inc();
    st.shared.record_config_event(
        "cache_clear",
        json!({
            "entries_dropped": before,
            "memory_bytes_freed": mem,
            "outcome": "applied"
        }),
    );
    Ok(Json(json!({
        "status": "ok",
        "entries_dropped": before,
        "memory_bytes_freed": mem,
    })))
}

// ---------------------------------------------------------------------------
// Cache settings (hot-reloadable TTL bounds / capacity / enable flag)
// ---------------------------------------------------------------------------

/// GET /api/cache — live cache state + the settings that control it.
pub(super) async fn get_cache(State(st): State<ApiState>) -> Json<Value> {
    let rt = st.shared.rt.load();
    Json(json!({
        "enabled": rt.cache.enabled,
        "entries": st.shared.cache.len(),
        "max_entries": rt.cache.max_entries,
        "max_memory_bytes": rt.cache.max_memory_bytes,
        "min_ttl_secs": rt.cache.min_ttl_secs,
        "max_ttl_secs": rt.cache.max_ttl_secs,
        "negative_max_ttl_secs": rt.cache.negative_max_ttl_secs,
        "memory_bytes": st.shared.cache.memory_bytes(),
        "generation": st.shared.config_generation(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CacheUpdateRequest {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    max_entries: Option<usize>,
    #[serde(default)]
    max_memory_bytes: Option<usize>,
    #[serde(default)]
    min_ttl_secs: Option<u64>,
    #[serde(default)]
    max_ttl_secs: Option<u64>,
    #[serde(default)]
    negative_max_ttl_secs: Option<u64>,
    generation: Option<u64>,
}

/// PUT /api/cache — update cache settings, apply at runtime, persist
/// atomically. Lowering `max_entries` trims the live cache immediately;
/// disabling the cache clears it.
pub(super) async fn put_cache(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<AclPutQuery>,
    Json(req): Json<CacheUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "cache_update")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation.or(q.generation), "cache_update")?;

    let mut next = AppConfig::clone(st.shared.app.load().as_ref());
    if let Some(enabled) = req.enabled {
        next.cache.enabled = enabled;
    }
    if let Some(max_entries) = req.max_entries {
        next.cache.max_entries = max_entries;
    }
    if let Some(max_memory_bytes) = req.max_memory_bytes {
        next.cache.max_memory_bytes = max_memory_bytes;
    }
    if let Some(min_ttl_secs) = req.min_ttl_secs {
        next.cache.min_ttl_secs = min_ttl_secs;
    }
    if let Some(max_ttl_secs) = req.max_ttl_secs {
        next.cache.max_ttl_secs = max_ttl_secs;
    }
    if let Some(negative_max_ttl_secs) = req.negative_max_ttl_secs {
        next.cache.negative_max_ttl_secs = negative_max_ttl_secs;
    }
    if let Err(e) = crate::shared::Shared::validate_config(&mut next) {
        return Err(reject(
            &st,
            "cache_update_rejected",
            json!({ "op": "cache_update" }),
            ApiError::BadRequest(e),
        ));
    }
    let persisted = commit_config(&st, next).await?;
    st.shared.record_config_event(
        "cache_update",
        json!({
            "enabled": req.enabled,
            "max_entries": req.max_entries,
            "max_memory_bytes": req.max_memory_bytes,
            "min_ttl_secs": req.min_ttl_secs,
            "max_ttl_secs": req.max_ttl_secs,
            "negative_max_ttl_secs": req.negative_max_ttl_secs,
            "persisted": persisted,
            "outcome": "applied",
        }),
    );
    let rt = st.shared.rt.load();
    Ok(Json(json!({
        "status": "ok",
        "enabled": rt.cache.enabled,
        "entries": st.shared.cache.len(),
        "max_entries": rt.cache.max_entries,
        "max_memory_bytes": rt.cache.max_memory_bytes,
        "min_ttl_secs": rt.cache.min_ttl_secs,
        "max_ttl_secs": rt.cache.max_ttl_secs,
        "negative_max_ttl_secs": rt.cache.negative_max_ttl_secs,
        "memory_bytes": st.shared.cache.memory_bytes(),
        "persisted": persisted,
        "persist_error": Value::Null,
        "generation": st.shared.config_generation(),
    })))
}
