//! Configuration export/import: secrets are never exported and an import that
//! omits them must not silently erase the running values.

#![allow(dead_code)]

mod common;

use common::*;
use serde_json::{json, Value};

const TOKEN: &str = "import-token";

fn put_import(body: Value) -> String {
    body.to_string()
}

struct Env {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
        let _ = std::fs::remove_dir_all(self.dir.with_extension("moved"));
    }
}

async fn start(
    tag: &str,
) -> (
    res::runtime::Gateway,
    Env,
    std::net::SocketAddr,
    FakeUpstream,
) {
    let fake = FakeUpstream::start().await;
    let dir = std::env::temp_dir().join(format!("res-import-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let path = dir.join("res.toml");
    let mut cfg = base_config();
    cfg.server.api_token = TOKEN.into();
    cfg.proxy.username = "proxy-user".into();
    cfg.proxy.password = "proxy-secret".into();
    cfg.upstreams.push(fake.config("seed"));
    std::fs::write(&path, cfg.to_toml().unwrap()).expect("seed file");
    let gw = start_gateway_with_path(cfg, path.clone()).await;
    let api = gw.api_addr().expect("api addr");
    (gw, Env { dir, path }, api, fake)
}

async fn export_toml(api: std::net::SocketAddr) -> String {
    let (status, body) = http_auth("GET", api, "/api/config", None, Some(TOKEN)).await;
    assert_eq!(status, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    v["toml"].as_str().unwrap().to_string()
}

async fn import(api: std::net::SocketAddr, body: Value) -> (u16, Value) {
    let (status, text) = http_auth(
        "PUT",
        api,
        "/api/config",
        Some(&put_import(body)),
        Some(TOKEN),
    )
    .await;
    let v = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, v)
}

async fn proxy_state(api: std::net::SocketAddr) -> Value {
    let (status, body) = http_auth("GET", api, "/api/proxy", None, Some(TOKEN)).await;
    assert_eq!(status, 200, "{body}");
    serde_json::from_str(&body).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn export_contains_no_secrets_for_any_caller() {
    let (gw, _env, api, _fake) = start("noleak").await;
    let toml = export_toml(api).await;
    assert!(!toml.contains("proxy-secret"), "{toml}");
    assert!(!toml.contains(TOKEN), "{toml}");
    assert!(!toml.contains("api_token"), "{toml}");
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn export_then_import_preserves_proxy_password_and_token() {
    let (gw, env, api, _fake) = start("roundtrip").await;
    let toml = export_toml(api).await;
    let (status, v) = import(api, json!({ "toml": toml })).await;
    assert_eq!(status, 200, "{v}");
    let kept: Vec<&str> = v["secrets_preserved"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|x| x.as_str())
        .collect();
    assert!(
        kept.contains(&"proxy.password") && kept.contains(&"server.api_token"),
        "{v}"
    );
    assert_eq!(proxy_state(api).await["password_set"], true);
    // Persisted file keeps both secrets.
    let on_disk = res::config::AppConfig::load(&env.path).expect("reload");
    assert_eq!(on_disk.proxy.password, "proxy-secret");
    assert_eq!(on_disk.server.api_token, TOKEN);
    // The bearer token still authenticates after the import.
    let (status, _) = http_auth("GET", api, "/api/status", None, Some(TOKEN)).await;
    assert_eq!(status, 200);
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_password_in_import_replaces_the_old_one() {
    let (gw, env, api, _fake) = start("replace").await;
    let toml = export_toml(api).await;
    let toml = toml.replace(
        "username = \"proxy-user\"",
        "username = \"proxy-user\"\npassword = \"brand-new\"",
    );
    assert!(toml.contains("brand-new"), "fixture edit applied: {toml}");
    let (status, v) = import(api, json!({ "toml": toml })).await;
    assert_eq!(status, 200, "{v}");
    let on_disk = res::config::AppConfig::load(&env.path).expect("reload");
    assert_eq!(on_disk.proxy.password, "brand-new");
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changed_username_never_inherits_the_old_password() {
    let (gw, env, api, _fake) = start("rename").await;
    let toml = export_toml(api).await.replace("proxy-user", "other-user");
    let (status, v) = import(api, json!({ "toml": toml })).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(proxy_state(api).await["password_set"], false);
    let on_disk = res::config::AppConfig::load(&env.path).expect("reload");
    assert_eq!(on_disk.proxy.username, "other-user");
    assert_eq!(on_disk.proxy.password, "");
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clear_secrets_removes_the_password_explicitly() {
    let (gw, env, api, _fake) = start("clear").await;
    let toml = export_toml(api).await;
    let (status, v) = import(
        api,
        json!({ "toml": toml, "clear_secrets": ["proxy_password"] }),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(proxy_state(api).await["password_set"], false);
    assert_eq!(
        res::config::AppConfig::load(&env.path)
            .unwrap()
            .proxy
            .password,
        ""
    );
    // The token was not listed, so it survived.
    assert_eq!(
        res::config::AppConfig::load(&env.path)
            .unwrap()
            .server
            .api_token,
        TOKEN
    );
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_clear_secret_is_rejected() {
    let (gw, _env, api, _fake) = start("badclear").await;
    let toml = export_toml(api).await;
    let (status, _) = import(
        api,
        json!({ "toml": toml, "clear_secrets": ["root_password"] }),
    )
    .await;
    assert!(status == 400 || status == 422, "got {status}");
    assert_eq!(proxy_state(api).await["password_set"], true);
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_import_leaves_secrets_and_generation_untouched() {
    let (gw, env, api, _fake) = start("failed").await;
    let (_, before) = http_auth("GET", api, "/api/status", None, Some(TOKEN)).await;
    let before: Value = serde_json::from_str(&before).unwrap();
    let (status, v) = import(api, json!({ "toml": "this is = not [valid toml" })).await;
    assert_eq!(status, 400, "{v}");
    // Unknown section: rejected by strict parsing.
    let toml = format!("{}\n[bogus_section]\nx = 1\n", export_toml(api).await);
    let (status, v) = import(api, json!({ "toml": toml })).await;
    assert_eq!(status, 400, "{v}");
    assert_eq!(proxy_state(api).await["password_set"], true);
    let (_, after) = http_auth("GET", api, "/api/status", None, Some(TOKEN)).await;
    let after: Value = serde_json::from_str(&after).unwrap();
    assert_eq!(
        after["config"]["generation"],
        before["config"]["generation"]
    );
    assert_eq!(
        res::config::AppConfig::load(&env.path)
            .unwrap()
            .proxy
            .password,
        "proxy-secret"
    );
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistence_failure_keeps_runtime_secrets_and_applies_nothing() {
    let (gw, env, api, _fake) = start("persistfail").await;
    let toml = export_toml(api).await.replace("proxy-user", "changed-user");
    // Deterministic for root and non-root: remove the config directory.
    let moved = env.dir.with_extension("moved");
    let _ = std::fs::remove_dir_all(&moved);
    std::fs::rename(&env.dir, &moved).expect("move dir");
    // A regular file where the directory was: the atomic writer can neither
    // create the directory nor a temp file in it (ENOTDIR), for any user.
    std::fs::write(&env.dir, b"not a directory").expect("blocker file");
    let (status, v) = import(api, json!({ "toml": toml })).await;
    assert_eq!(status, 500, "{v}");
    assert_eq!(v["code"], "persist_failed", "{v}");
    let p = proxy_state(api).await;
    assert_eq!(
        p["username"], "proxy-user",
        "runtime must be unchanged: {p}"
    );
    assert_eq!(p["password_set"], true, "{p}");
    std::fs::remove_file(&env.dir).expect("remove blocker");
    std::fs::rename(&moved, &env.dir).expect("restore dir");
    assert_eq!(
        res::config::AppConfig::load(&env.path)
            .unwrap()
            .proxy
            .password,
        "proxy-secret"
    );
    gw.shutdown().await;
}
