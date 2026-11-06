//! Dashboard static assets over HTTP: caching, ETag revalidation, compression
//! and the invariants that must survive them (CSP/security headers, API
//! responses stay `no-store`).

#![allow(dead_code)]

mod common;

use common::*;

fn header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    raw.split("\r\n").find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn assets_are_cached_compressed_and_keep_security_headers() {
    let dir = std::env::temp_dir().join(format!("res-static-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.html"), "<!doctype html><title>t</title>").unwrap();
    let js = "console.log('dashboard');\n".repeat(100);
    std::fs::write(dir.join("app.js"), &js).unwrap();

    let mut cfg = base_config();
    cfg.server.dashboard_dir = Some(dir.clone());
    cfg.server.api_token = "tok".into();
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().unwrap();

    // Plain fetch: validators, revalidation policy, CSP and friends intact.
    let raw = http_raw("GET", api, "/app.js", None, &[]).await;
    assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
    let etag = header(&raw, "etag").expect("etag").to_string();
    assert_eq!(header(&raw, "cache-control"), Some("no-cache"));
    assert_eq!(header(&raw, "vary"), Some("Accept-Encoding"));
    assert!(header(&raw, "content-security-policy")
        .unwrap()
        .contains("script-src 'self'"));
    assert_eq!(header(&raw, "x-content-type-options"), Some("nosniff"));
    assert_eq!(header(&raw, "x-frame-options"), Some("DENY"));
    assert!(header(&raw, "content-encoding").is_none());

    // Conditional request -> 304 with no body.
    let raw = http_raw(
        "GET",
        api,
        "/app.js",
        None,
        &[("If-None-Match".into(), etag.clone())],
    )
    .await;
    assert!(raw.starts_with("HTTP/1.1 304"), "{raw}");
    assert!(header(&raw, "content-security-policy").is_some());

    // Compression is negotiated.
    let raw = http_raw(
        "GET",
        api,
        "/app.js",
        None,
        &[("Accept-Encoding".into(), "gzip, br".into())],
    )
    .await;
    assert_eq!(header(&raw, "content-encoding"), Some("br"), "{raw}");
    let clen: usize = header(&raw, "content-length").unwrap().parse().unwrap();
    assert!(clen < js.len() / 4, "compressed {clen} vs {}", js.len());
    assert_ne!(header(&raw, "etag").unwrap(), etag, "per-encoding ETag");

    // SPA entry point also revalidates.
    let raw = http_raw("GET", api, "/", None, &[]).await;
    assert_eq!(header(&raw, "cache-control"), Some("no-cache"));

    // API and metrics responses are never cacheable and never carry an ETag.
    for path in ["/api/health", "/api/status"] {
        let raw = http_raw(
            "GET",
            api,
            path,
            None,
            &[("Authorization".into(), "Bearer tok".into())],
        )
        .await;
        assert_eq!(
            header(&raw, "cache-control"),
            Some("no-store"),
            "{path}: {raw}"
        );
        assert!(header(&raw, "etag").is_none(), "{path}");
        assert!(header(&raw, "content-encoding").is_none(), "{path}");
    }
    // Unknown API paths stay a JSON 404, not the SPA shell.
    let raw = http_raw("GET", api, "/api/nope", None, &[]).await;
    assert!(raw.starts_with("HTTP/1.1 404"), "{raw}");
    assert!(
        raw.contains("no_route") || raw.contains("not_found"),
        "{raw}"
    );

    // Cache invalidation after a dashboard update.
    std::fs::write(
        dir.join("app.js"),
        "console.log('v2 of the dashboard');\n".repeat(100),
    )
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
    let raw = http_raw(
        "GET",
        api,
        "/app.js",
        None,
        &[("If-None-Match".into(), etag)],
    )
    .await;
    assert!(
        raw.starts_with("HTTP/1.1 200"),
        "stale ETag must be refreshed: {raw}"
    );
    assert!(raw.contains("v2 of the dashboard"));

    gw.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
