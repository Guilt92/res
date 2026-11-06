//! Dashboard static-asset serving.
//!
//! * Files are read **asynchronously** and kept in memory; a request never
//!   blocks a runtime worker on disk I/O.
//! * Each asset is pre-compressed once (gzip and Brotli) when it is loaded and
//!   served according to `Accept-Encoding`; already-compressed formats and tiny
//!   files are sent as-is.
//! * Strong `ETag`s (content hash, one per encoding variant) and
//!   `If-None-Match` handling give cheap `304 Not Modified` revalidation.
//! * Invalidation: a cached entry is re-validated against the file's
//!   `(mtime, length)` at most once per [`REVALIDATE`] interval, so editing or
//!   replacing a dashboard file is picked up without a restart, while a busy
//!   dashboard costs no filesystem calls per request.
//! * Only static, non-secret files are served here. API and metrics responses
//!   never pass through this module and keep `Cache-Control: no-store` (set by
//!   the security-headers middleware); this module sets its own cache headers
//!   on asset responses only.
//!
//! The path rules of the previous implementation are unchanged: `..`, empty
//! and dot-prefixed segments are refused, unknown `/api/*` paths answer a JSON
//! 404, a missing asset (name with an extension) is a visible 404 and only
//! extensionless paths fall back to `index.html`. Additionally the resolved
//! file must stay inside the dashboard directory after symlink resolution.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use axum::body::{Body, Bytes};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use super::ApiError;

/// How often a cached asset is re-checked against the file on disk.
const REVALIDATE: Duration = Duration::from_secs(1);
/// Files larger than this are not served (the dashboard is a few hundred KB).
const MAX_ASSET_BYTES: u64 = 8 * 1024 * 1024;
/// Below this size compression costs more than it saves.
const MIN_COMPRESS_BYTES: usize = 256;

struct Asset {
    mime: &'static str,
    cache_control: &'static str,
    identity: Bytes,
    gzip: Option<Bytes>,
    brotli: Option<Bytes>,
    etag: String,
    modified: Option<SystemTime>,
    len: u64,
    checked: Mutex<Instant>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Identity,
    Gzip,
    Brotli,
}

impl Encoding {
    fn header(self) -> Option<&'static str> {
        match self {
            Encoding::Identity => None,
            Encoding::Gzip => Some("gzip"),
            Encoding::Brotli => Some("br"),
        }
    }
}

/// In-memory, self-invalidating cache of the dashboard directory.
pub struct Assets {
    root: PathBuf,
    /// Symlink-resolved root used for the containment check.
    canonical_root: PathBuf,
    cache: RwLock<HashMap<PathBuf, Arc<Asset>>>,
}

impl Assets {
    pub fn new(root: PathBuf) -> Self {
        // One-time startup cost; a blocking call is fine here.
        let canonical_root = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
        Self {
            root,
            canonical_root,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Number of assets currently held in memory (tests).
    #[cfg(test)]
    pub fn cached(&self) -> usize {
        self.cache.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub async fn serve(&self, method: &Method, uri_path: &str, headers: &HeaderMap) -> Response {
        if uri_path.starts_with("/api/") || uri_path == "/metrics" {
            return ApiError::NotFound(format!("no route for {uri_path}")).into_response();
        }
        if method != Method::GET && method != Method::HEAD {
            return (
                StatusCode::METHOD_NOT_ALLOWED,
                Json(json!({
                    "error": "method not allowed",
                    "code": "method_not_allowed",
                })),
            )
                .into_response();
        }

        let rel = uri_path.trim_start_matches('/');
        let mut file = self.root.clone();
        let mut last_seg = "";
        if !rel.is_empty() {
            for seg in rel.split('/') {
                if seg.is_empty() || seg == "." || seg == ".." || seg.starts_with('.') {
                    return ApiError::NotFound(format!("no route for {uri_path}")).into_response();
                }
                file.push(seg);
                last_seg = seg;
            }
        }

        let head = method == Method::HEAD;
        if let Some(asset) = self.lookup(&file).await {
            return respond(&asset, headers, head);
        }
        if last_seg.contains('.') {
            // A missing asset must be a visible failure, not a silently
            // rendered HTML page.
            return ApiError::NotFound(format!("asset not found: {uri_path}")).into_response();
        }
        let index = self.root.join("index.html");
        match self.lookup(&index).await {
            Some(asset) => respond(&asset, headers, head),
            None => ApiError::Internal("index.html unreadable".into()).into_response(),
        }
    }

    /// Return the (possibly refreshed) cached asset for `path`, or `None`
    /// when it does not exist, is not a regular file, is too large or
    /// resolves outside the dashboard directory.
    async fn lookup(&self, path: &Path) -> Option<Arc<Asset>> {
        let cached = self
            .cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(path)
            .cloned();
        if let Some(a) = &cached {
            let fresh = a
                .checked
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .elapsed()
                < REVALIDATE;
            if fresh {
                return cached;
            }
        }

        let meta = match tokio::fs::metadata(path).await {
            Ok(m) if m.is_file() && m.len() <= MAX_ASSET_BYTES => m,
            _ => {
                self.cache
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(path);
                return None;
            }
        };
        let modified = meta.modified().ok();
        if let Some(a) = cached {
            if a.modified == modified && a.len == meta.len() {
                *a.checked.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
                return Some(a);
            }
        }

        // Cache miss or changed on disk: reload. Symlinks must not lead out of
        // the dashboard directory.
        let real = tokio::fs::canonicalize(path).await.ok()?;
        if !real.starts_with(&self.canonical_root) {
            return None;
        }
        let data = tokio::fs::read(&real).await.ok()?;
        let mime = mime_for(path);
        let cache_control = cache_control_for(mime);
        let len = meta.len();
        let asset = tokio::task::spawn_blocking(move || {
            build_asset(data, mime, cache_control, modified, len)
        })
        .await
        .ok()?;
        let asset = Arc::new(asset);
        self.cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(path.to_path_buf(), Arc::clone(&asset));
        Some(asset)
    }
}

fn build_asset(
    data: Vec<u8>,
    mime: &'static str,
    cache_control: &'static str,
    modified: Option<SystemTime>,
    len: u64,
) -> Asset {
    let etag = format!("{:016x}-{:x}", fnv1a(&data), data.len());
    let compressible = is_compressible(mime) && data.len() >= MIN_COMPRESS_BYTES;
    let (gzip, brotli) = if compressible {
        (gzip_bytes(&data), brotli_bytes(&data))
    } else {
        (None, None)
    };
    Asset {
        mime,
        cache_control,
        identity: Bytes::from(data),
        // Keep a variant only when it is actually smaller.
        gzip: gzip.filter(|g| g.len() < len as usize).map(Bytes::from),
        brotli: brotli.filter(|b| b.len() < len as usize).map(Bytes::from),
        etag,
        modified,
        len,
        checked: Mutex::new(Instant::now()),
    }
}

fn gzip_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(data).ok()?;
    enc.finish().ok()
}

fn brotli_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    {
        // quality 9, 22-bit window: near-best ratio at a modest load-time cost.
        let mut w = brotli::CompressorWriter::new(&mut out, 4096, 9, 22);
        w.write_all(data).ok()?;
        w.flush().ok()?;
    }
    Some(out)
}

/// 64-bit FNV-1a: a fast, deterministic content fingerprint for ETags (not a
/// security primitive; assets are public files).
fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn mime_for(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("ttf") => "font/ttf",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("json") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn is_compressible(mime: &str) -> bool {
    mime.starts_with("text/")
        || mime.starts_with("application/javascript")
        || mime.starts_with("application/json")
        || mime == "image/svg+xml"
        || mime == "font/ttf"
        || mime == "image/x-icon"
}

/// HTML/CSS/JS are not fingerprinted in their file names, so they must be
/// revalidated on every use (cheap thanks to the ETag). Binary assets such as
/// fonts change rarely and may be reused for a day.
fn cache_control_for(mime: &str) -> &'static str {
    if mime.starts_with("font/") || mime.starts_with("image/") {
        "public, max-age=86400"
    } else {
        "no-cache"
    }
}

/// Pick the best supported content-coding from `Accept-Encoding`
/// (`q=0` excludes a coding; `*` is not treated as a wildcard grant).
fn negotiate(headers: &HeaderMap, asset: &Asset) -> Encoding {
    let mut br = false;
    let mut gz = false;
    for v in headers.get_all(header::ACCEPT_ENCODING) {
        let Ok(v) = v.to_str() else { continue };
        for part in v.split(',') {
            let mut it = part.split(';');
            let coding = it.next().unwrap_or("").trim().to_ascii_lowercase();
            let q_zero = it.any(|p| {
                let p = p.trim();
                p.strip_prefix("q=")
                    .and_then(|q| q.trim().parse::<f32>().ok())
                    .is_some_and(|q| q <= 0.0)
            });
            if q_zero {
                continue;
            }
            match coding.as_str() {
                "br" => br = true,
                "gzip" | "x-gzip" => gz = true,
                _ => {}
            }
        }
    }
    if br && asset.brotli.is_some() {
        Encoding::Brotli
    } else if gz && asset.gzip.is_some() {
        Encoding::Gzip
    } else {
        Encoding::Identity
    }
}

fn etag_for(asset: &Asset, enc: Encoding) -> String {
    match enc {
        Encoding::Identity => format!("\"{}\"", asset.etag),
        Encoding::Gzip => format!("\"{}-gzip\"", asset.etag),
        Encoding::Brotli => format!("\"{}-br\"", asset.etag),
    }
}

/// `If-None-Match` evaluation using weak comparison (RFC 9110 §13.1.2).
fn not_modified(headers: &HeaderMap, etag: &str) -> bool {
    let Some(v) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    v.split(',').any(|t| {
        let t = t.trim();
        t == "*" || t.strip_prefix("W/").unwrap_or(t) == etag
    })
}

fn respond(asset: &Asset, headers: &HeaderMap, head: bool) -> Response {
    let enc = negotiate(headers, asset);
    let etag = etag_for(asset, enc);
    let mut h = HeaderMap::new();
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(asset.cache_control),
    );
    h.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    if not_modified(headers, &etag) {
        return (StatusCode::NOT_MODIFIED, h).into_response();
    }
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(asset.mime));
    let body = match enc {
        Encoding::Identity => asset.identity.clone(),
        Encoding::Gzip => asset.gzip.clone().unwrap_or_else(|| asset.identity.clone()),
        Encoding::Brotli => asset
            .brotli
            .clone()
            .unwrap_or_else(|| asset.identity.clone()),
    };
    if let Some(name) = enc.header() {
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static(name));
    }
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    let body = if head {
        Body::empty()
    } else {
        Body::from(body)
    };
    (StatusCode::OK, h, body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "res-assets-{tag}-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn hdrs(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    async fn body(r: Response) -> Vec<u8> {
        axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[test]
    fn fingerprint_is_deterministic_and_content_sensitive() {
        assert_eq!(fnv1a(b"abc"), fnv1a(b"abc"));
        assert_ne!(fnv1a(b"abc"), fnv1a(b"abd"));
    }

    #[tokio::test]
    async fn serves_etag_and_304_and_invalidates_on_change() {
        let d = dir("etag");
        std::fs::write(d.join("index.html"), "<html>v1</html>").unwrap();
        let a = Assets::new(d.clone());
        let r = a.serve(&Method::GET, "/", &HeaderMap::new()).await;
        assert_eq!(r.status(), 200);
        let etag = r.headers()[header::ETAG].to_str().unwrap().to_string();
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(body(r).await, b"<html>v1</html>");

        let r = a
            .serve(&Method::GET, "/", &hdrs(&[("if-none-match", &etag)]))
            .await;
        assert_eq!(r.status(), 304);
        assert_eq!(r.headers()[header::ETAG].to_str().unwrap(), etag);
        assert!(body(r).await.is_empty());

        // Replace the file (different length) and let the revalidation
        // interval pass: the new content and a new ETag are served.
        std::fs::write(d.join("index.html"), "<html>version two</html>").unwrap();
        tokio::time::sleep(REVALIDATE + Duration::from_millis(100)).await;
        let r = a
            .serve(&Method::GET, "/", &hdrs(&[("if-none-match", &etag)]))
            .await;
        assert_eq!(
            r.status(),
            200,
            "stale ETag must not yield 304 after a change"
        );
        assert_ne!(r.headers()[header::ETAG].to_str().unwrap(), etag);
        assert_eq!(body(r).await, b"<html>version two</html>");
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn compression_is_negotiated_and_round_trips() {
        let d = dir("gz");
        let js = "function hello(){return 'hello world';}\n".repeat(200);
        std::fs::write(d.join("app.js"), &js).unwrap();
        std::fs::write(d.join("index.html"), "x").unwrap();
        let a = Assets::new(d.clone());

        let r = a
            .serve(
                &Method::GET,
                "/app.js",
                &hdrs(&[("accept-encoding", "gzip, br")]),
            )
            .await;
        assert_eq!(r.headers()[header::CONTENT_ENCODING], "br");
        assert_eq!(r.headers()[header::VARY], "Accept-Encoding");
        let br = body(r).await;
        assert!(br.len() < js.len() / 4);
        let mut plain = Vec::new();
        brotli::BrotliDecompress(&mut std::io::Cursor::new(br), &mut plain).unwrap();
        assert_eq!(plain, js.as_bytes());

        let r = a
            .serve(
                &Method::GET,
                "/app.js",
                &hdrs(&[("accept-encoding", "gzip;q=1.0")]),
            )
            .await;
        assert_eq!(r.headers()[header::CONTENT_ENCODING], "gzip");
        let gz = body(r).await;
        let mut dec = flate2::read::GzDecoder::new(&gz[..]);
        let mut plain = String::new();
        std::io::Read::read_to_string(&mut dec, &mut plain).unwrap();
        assert_eq!(plain, js);

        // q=0 disables a coding; no header means identity.
        let r = a
            .serve(
                &Method::GET,
                "/app.js",
                &hdrs(&[("accept-encoding", "br;q=0, gzip;q=0")]),
            )
            .await;
        assert!(r.headers().get(header::CONTENT_ENCODING).is_none());
        let r = a.serve(&Method::GET, "/app.js", &HeaderMap::new()).await;
        assert!(r.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(body(r).await, js.as_bytes());

        // Variants have distinct ETags.
        let e1 = a
            .serve(&Method::GET, "/app.js", &hdrs(&[("accept-encoding", "br")]))
            .await
            .headers()[header::ETAG]
            .clone();
        let e2 = a
            .serve(&Method::GET, "/app.js", &HeaderMap::new())
            .await
            .headers()[header::ETAG]
            .clone();
        assert_ne!(e1, e2);
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn path_rules_and_fallbacks() {
        let d = dir("paths");
        std::fs::write(d.join("index.html"), "<html></html>").unwrap();
        std::fs::write(d.join(".secret"), "no").unwrap();
        let a = Assets::new(d.clone());
        let get = |p: &'static str| {
            let a = &a;
            async move {
                a.serve(&Method::GET, p, &HeaderMap::new())
                    .await
                    .status()
                    .as_u16()
            }
        };
        assert_eq!(get("/").await, 200);
        assert_eq!(
            get("/some/spa/route").await,
            200,
            "extensionless falls back to index"
        );
        assert_eq!(
            get("/missing.js").await,
            404,
            "missing asset is a visible 404"
        );
        assert_eq!(get("/.secret").await, 404);
        assert_eq!(get("/../etc/passwd").await, 404);
        assert_eq!(get("/api/nope").await, 404);
        assert_eq!(get("/metrics").await, 404);
        assert_eq!(
            a.serve(&Method::POST, "/", &HeaderMap::new())
                .await
                .status(),
            405
        );
        let h = a.serve(&Method::HEAD, "/", &HeaderMap::new()).await;
        assert_eq!(h.status(), 200);
        assert_eq!(h.headers()[header::CONTENT_LENGTH], "13");
        assert!(body(h).await.is_empty());
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_cannot_escape_the_dashboard_directory() {
        let d = dir("symlink");
        let outside = dir("outside");
        std::fs::write(outside.join("secret.txt"), "top secret").unwrap();
        std::fs::write(d.join("index.html"), "ok").unwrap();
        std::os::unix::fs::symlink(outside.join("secret.txt"), d.join("leak.txt")).unwrap();
        let a = Assets::new(d.clone());
        let r = a.serve(&Method::GET, "/leak.txt", &HeaderMap::new()).await;
        assert_eq!(r.status(), 404);
        let _ = std::fs::remove_dir_all(d);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[tokio::test]
    async fn deleted_file_stops_being_served() {
        let d = dir("deleted");
        std::fs::write(d.join("index.html"), "ok").unwrap();
        std::fs::write(d.join("a.css"), "body{}").unwrap();
        let a = Assets::new(d.clone());
        assert_eq!(
            a.serve(&Method::GET, "/a.css", &HeaderMap::new())
                .await
                .status(),
            200
        );
        assert_eq!(a.cached(), 1);
        std::fs::remove_file(d.join("a.css")).unwrap();
        tokio::time::sleep(REVALIDATE + Duration::from_millis(100)).await;
        assert_eq!(
            a.serve(&Method::GET, "/a.css", &HeaderMap::new())
                .await
                .status(),
            404
        );
        assert_eq!(a.cached(), 0);
        let _ = std::fs::remove_dir_all(d);
    }
}
