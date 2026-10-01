//! Minimal Prometheus HTTP client for the dashboard time-series proxy.
//!
//! Deliberately hand-rolled on `tokio::net::TcpStream`: the gateway must not
//! pull in a full HTTP client stack for two GET requests per dashboard
//! refresh. Supports plain `http://` only (Prometheus in the compose stack
//! is plain HTTP on the internal network); `https://` is rejected with a
//! clear error.

use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_RESPONSE: usize = 32 * 1024 * 1024; // 32 MiB safety cap

#[derive(Clone, Debug)]
pub struct PromClient {
    host: String,
    port: u16,
    base_path: String,
    timeout: Duration,
}

impl PromClient {
    /// Parse a base URL like `http://prometheus:9090` (path prefix allowed).
    pub fn new(base_url: &str) -> Result<Self, String> {
        let url = base_url.trim().trim_end_matches('/');
        let rest = url.strip_prefix("http://").ok_or_else(|| {
            format!("unsupported Prometheus URL '{base_url}' (only plain http:// is supported)")
        })?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| format!("invalid port in '{base_url}'"))?,
            ),
            None => (authority.to_string(), 80),
        };
        if host.is_empty() {
            return Err(format!("missing host in '{base_url}'"));
        }
        Ok(Self {
            host,
            port,
            base_path: path.trim_end_matches('/').to_string(),
            timeout: Duration::from_secs(5),
        })
    }

    fn endpoint(&self) -> String {
        format!("{}:{}/api/v1", self.host, self.port)
    }

    /// `GET /api/v1/query_range?query=…&start=…&end=…&step=…`
    /// Returns the JSON `data.result` array (matrix).
    pub async fn query_range(
        &self,
        query: &str,
        start: f64,
        end: f64,
        step_secs: u64,
    ) -> Result<Value, String> {
        let path = format!(
            "{}/query_range?query={}&start={}&end={}&step={}",
            self.prefix(),
            urlencode(query),
            start,
            end,
            step_secs
        );
        let body = self.get(&path).await?;
        let v: Value =
            serde_json::from_slice(&body).map_err(|e| format!("invalid Prometheus JSON: {e}"))?;
        match v.get("status").and_then(|s| s.as_str()) {
            Some("success") => Ok(v
                .pointer("/data/result")
                .cloned()
                .unwrap_or(Value::Array(vec![]))),
            Some(other) => {
                let err = v
                    .get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("unknown error");
                Err(format!("Prometheus error ({other}): {err}"))
            }
            None => Err("unexpected Prometheus response (no status field)".into()),
        }
    }

    /// Cheap reachability check (`query=1` returns instantly).
    pub async fn probe(&self) -> Result<(), String> {
        let path = format!("{}/query?query={}", self.prefix(), urlencode("1"));
        let body = self.get(&path).await?;
        let v: Value =
            serde_json::from_slice(&body).map_err(|e| format!("invalid Prometheus JSON: {e}"))?;
        match v.get("status").and_then(|s| s.as_str()) {
            Some("success") => Ok(()),
            _ => Err("unexpected probe response".into()),
        }
    }

    fn prefix(&self) -> String {
        format!("{}/api/v1", self.base_path)
    }

    async fn get(&self, path_and_query: &str) -> Result<Vec<u8>, String> {
        let fut = async {
            let mut stream = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|e| format!("connect to {}: {e}", self.endpoint()))?;
            let req = format!(
                "GET {path_and_query} HTTP/1.1\r\nHost: {}\r\nUser-Agent: res/{}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
                if self.port == 80 {
                    self.host.clone()
                } else {
                    format!("{}:{}", self.host, self.port)
                },
                env!("CARGO_PKG_VERSION"),
            );
            stream
                .write_all(req.as_bytes())
                .await
                .map_err(|e| format!("write to {}: {e}", self.endpoint()))?;
            let mut buf = Vec::with_capacity(8192);
            let mut chunk = [0u8; 8192];
            loop {
                let n = stream
                    .read(&mut chunk)
                    .await
                    .map_err(|e| format!("read from {}: {e}", self.endpoint()))?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_RESPONSE {
                    return Err(format!(
                        "response from {} exceeds {MAX_RESPONSE} bytes",
                        self.endpoint()
                    ));
                }
            }
            parse_http_response(&buf)
        };
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(r) => r,
            Err(_) => Err(format!(
                "timeout talking to {} after {:?}",
                self.endpoint(),
                self.timeout
            )),
        }
    }
}

fn parse_http_response(raw: &[u8]) -> Result<Vec<u8>, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response (no header terminator)".to_string())?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| "non-UTF-8 HTTP headers")?;
    let body = &raw[split + 4..];

    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| "malformed HTTP status line".to_string())?;
    if status != 200 {
        return Err(format!("HTTP {status} from Prometheus"));
    }

    let chunked = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    if chunked {
        decode_chunked(body)
    } else if let Some(cl) = head.lines().find_map(|l| {
        let l = l.to_ascii_lowercase();
        l.strip_prefix("content-length:")
            .and_then(|v| v.trim().parse::<usize>().ok())
    }) {
        if body.len() < cl {
            return Err("truncated HTTP body".into());
        }
        Ok(body[..cl].to_vec())
    } else {
        Ok(body.to_vec())
    }
}

fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let eol = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "malformed chunked body".to_string())?;
        let size_line = std::str::from_utf8(&body[..eol]).map_err(|_| "bad chunk size")?;
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16).map_err(|_| format!("bad chunk size '{hex}'"))?;
        body = &body[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            return Err("truncated chunk".into());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
        if out.len() > MAX_RESPONSE {
            return Err("chunked response too large".into());
        }
    }
}

/// Percent-encode everything outside the unreserved set (safe inside a query
/// parameter value: braces, quotes, operators and spaces all get encoded).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// PromQL presets (one expression per canonical series key)
// ---------------------------------------------------------------------------

/// Canonical global series keys — must match the native history output.
pub const GLOBAL_SERIES: &[&str] = &[
    "qps",
    "success_pct",
    "error_pct",
    "servfail_pct",
    "deadline_pct",
    "timeout_pct",
    "failover_per_min",
    "rate_limited_per_min",
    "acl_denied_per_min",
    "overload_per_min",
    "malformed_per_min",
    "cache_hit_pct",
    "p50_ms",
    "p95_ms",
    "p99_ms",
    "inflight",
    "tcp_open",
    "rss_mb",
    "cpu_pct",
    "fds",
    "healthy",
    "degraded",
    "down",
    "cache_entries",
    "tcp_conn_per_min",
    "queries",
    "packets_in",
    "packets_out",
    "avg_req_bytes",
    "avg_resp_bytes",
    "nxdomain_pct",
    "refused_pct",
];

/// Canonical per-upstream series keys.
pub const UPSTREAM_SERIES: &[&str] = &[
    "qps",
    "p50_ms",
    "p95_ms",
    "timeout_pct",
    "failover_per_min",
    "state",
];

/// Global PromQL expressions for one rate window (`w` = `NNs`).
pub fn global_exprs(w: &str) -> Vec<(&'static str, String)> {
    let q = "res_queries_total";
    let r = "res_response_rcode_total";
    let ratio = |num: String, den: String| format!("100 * ({num}) / ({den})");
    vec![
        ("qps", format!("sum(rate({q}[{w}]))")),
        (
            "success_pct",
            ratio(
                format!("sum(rate({r}{{rcode=~\"NOERROR|NXDOMAIN\"}}[{w}]))"),
                format!("sum(rate({r}[{w}]))"),
            ),
        ),
        (
            "error_pct",
            ratio(
                format!("sum(rate({r}{{rcode!~\"NOERROR|NXDOMAIN\"}}[{w}]))"),
                format!("sum(rate({r}[{w}]))"),
            ),
        ),
        (
            "servfail_pct",
            ratio(
                format!("sum(rate({r}{{rcode=\"SERVFAIL\"}}[{w}]))"),
                format!("sum(rate({r}[{w}]))"),
            ),
        ),
        (
            "deadline_pct",
            ratio(
                format!("sum(rate(res_query_errors_total{{reason=\"deadline\"}}[{w}]))"),
                format!("sum(rate({q}[{w}]))"),
            ),
        ),
        (
            "timeout_pct",
            ratio(
                format!("sum(rate(res_upstream_timeouts_total[{w}]))"),
                format!("sum(rate({q}[{w}]))"),
            ),
        ),
        (
            "failover_per_min",
            format!("60 * sum(rate(res_failovers_total[{w}]))"),
        ),
        (
            "rate_limited_per_min",
            format!("60 * rate(res_rate_limit_dropped_total[{w}])"),
        ),
        (
            "acl_denied_per_min",
            format!("60 * rate(res_acl_denied_total[{w}])"),
        ),
        (
            "overload_per_min",
            format!("60 * rate(res_overload_dropped_total[{w}])"),
        ),
        (
            "malformed_per_min",
            format!("60 * rate(res_malformed_packets_total[{w}])"),
        ),
        (
            "cache_hit_pct",
            ratio(
                format!("rate(res_cache_hits_total[{w}])"),
                format!("(rate(res_cache_hits_total[{w}]) + rate(res_cache_misses_total[{w}]))"),
            ),
        ),
        (
            "p50_ms",
            quantile(0.50, w, "res_query_duration_seconds_bucket"),
        ),
        (
            "p95_ms",
            quantile(0.95, w, "res_query_duration_seconds_bucket"),
        ),
        (
            "p99_ms",
            quantile(0.99, w, "res_query_duration_seconds_bucket"),
        ),
        ("inflight", "res_udp_inflight".into()),
        ("tcp_open", "res_tcp_connections".into()),
        ("rss_mb", "res_resident_memory_bytes / 1048576".into()),
        ("cpu_pct", "res_cpu_percent".into()),
        ("fds", "res_open_fds".into()),
        ("healthy", "res_healthy_upstreams".into()),
        (
            "degraded",
            "sum(res_upstream_state == 1) or vector(0)".into(),
        ),
        ("down", "sum(res_upstream_state == 0) or vector(0)".into()),
        ("cache_entries", "res_cache_entries".into()),
        (
            "tcp_conn_per_min",
            format!("60 * rate(res_tcp_connections_total[{w}])"),
        ),
        ("queries", format!("increase({q}[{w}])")),
        (
            "packets_in",
            format!("rate(res_udp_packets_received_total[{w}])"),
        ),
        (
            "packets_out",
            format!("rate(res_udp_packets_sent_total[{w}])"),
        ),
        (
            "avg_req_bytes",
            format!("sum(rate(res_request_bytes_total[{w}])) / sum(rate({q}[{w}]))"),
        ),
        (
            "avg_resp_bytes",
            format!("sum(rate(res_response_bytes_total[{w}])) / sum(rate({r}[{w}]))"),
        ),
        (
            "nxdomain_pct",
            ratio(
                format!("sum(rate({r}{{rcode=\"NXDOMAIN\"}}[{w}]))"),
                format!("sum(rate({r}[{w}]))"),
            ),
        ),
        (
            "refused_pct",
            ratio(
                format!("sum(rate({r}{{rcode=\"REFUSED\"}}[{w}]))"),
                format!("sum(rate({r}[{w}]))"),
            ),
        ),
    ]
}

/// Per-upstream PromQL expressions for one upstream name and rate window.
pub fn upstream_exprs(name: &str, w: &str) -> Vec<(&'static str, String)> {
    let n = label_matcher(name);
    vec![
        (
            "qps",
            format!("sum(rate(res_upstream_queries_total{{upstream={n}}}[{w}]))"),
        ),
        (
            "p50_ms",
            quantile_for(0.50, w, &n, "res_upstream_latency_seconds_bucket"),
        ),
        (
            "p95_ms",
            quantile_for(0.95, w, &n, "res_upstream_latency_seconds_bucket"),
        ),
        (
            "timeout_pct",
            format!(
                "100 * sum(rate(res_upstream_timeouts_total{{upstream={n}}}[{w}])) / sum(rate(res_upstream_queries_total{{upstream={n}}}[{w}]))"
            ),
        ),
        (
            "failover_per_min",
            format!(
                "60 * sum(rate(res_upstream_failovers_total{{upstream={n}}}[{w}]))"
            ),
        ),
        (
            "state",
            format!("res_upstream_state{{upstream={n}}}"),
        ),
    ]
}

fn quantile(p: f64, w: &str, bucket_metric: &str) -> String {
    format!("1000 * histogram_quantile({p}, sum by (le) (rate({bucket_metric}[{w}])))")
}

fn quantile_for(p: f64, w: &str, matcher: &str, bucket_metric: &str) -> String {
    format!(
        "1000 * histogram_quantile({p}, sum by (le) (rate({bucket_metric}{{upstream={matcher}}}[{w}])))"
    )
}

/// Escape an upstream name for use inside a PromQL label matcher.
fn label_matcher(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    out.push('"');
    for c in name.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// Matrix result -> normalized points
// ---------------------------------------------------------------------------

/// Convert a Prometheus matrix into `[ts_ms, value]` points aligned to the
/// given timestamps (`None` values become JSON null).
pub fn matrix_to_points(result: &Value, ts_ms: &[u64]) -> Vec<Option<f64>> {
    let mut map: std::collections::HashMap<u64, Option<f64>> = std::collections::HashMap::new();
    if let Some(series) = result.as_array() {
        for s in series {
            if let Some(values) = s.get("values").and_then(|v| v.as_array()) {
                for pair in values {
                    if let (Some(t), Some(v)) = (pair.get(0).and_then(|t| t.as_f64()), pair.get(1))
                    {
                        let ts = (t * 1000.0).round() as u64;
                        let val = match v.as_str().and_then(|s| s.parse::<f64>().ok()) {
                            Some(f) if f.is_finite() => Some(f),
                            _ => None,
                        };
                        map.insert(ts, val);
                    }
                }
            }
        }
    }
    // Snap each sample to its nearest grid timestamp within half a step:
    // Prometheus may align range-query samples differently from the axis we
    // synthesize, and an exact-match lookup would silently drop them all.
    let tol = if ts_ms.len() > 1 {
        (ts_ms[1] - ts_ms[0]) / 2
    } else {
        0
    };
    ts_ms
        .iter()
        .map(|t| match map.get(t) {
            Some(v) => *v,
            None if tol > 0 => map
                .iter()
                .filter(|(k, _)| k.abs_diff(*t) <= tol)
                .min_by_key(|(k, _)| k.abs_diff(*t))
                .and_then(|(_, v)| *v),
            None => None,
        })
        .collect()
}

/// Synthesize the step-aligned timestamp axis (ms) for a `query_range`
/// window: `start, start+step, … <= end`.
///
/// The axis is derived from the *request*, never from a returned matrix —
/// otherwise identical requests could produce different grids (and therefore
/// different chart lengths) depending on which series carried data.
pub fn step_axis(start_s: f64, end_s: f64, step: u64) -> Vec<u64> {
    let mut ts = Vec::new();
    let mut t = start_s;
    while t <= end_s {
        ts.push((t * 1000.0).round() as u64);
        t += step as f64;
    }
    ts
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_base_urls() {
        let c = PromClient::new("http://prometheus:9090").unwrap();
        assert_eq!(c.host, "prometheus");
        assert_eq!(c.port, 9090);
        assert_eq!(c.base_path, "");
        let c = PromClient::new("http://127.0.0.1/").unwrap();
        assert_eq!(c.port, 80);
        assert!(PromClient::new("https://prom:9090").is_err());
        assert!(PromClient::new("").is_err());
    }

    #[test]
    fn encodes_query_strings() {
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("rate(x[5m])"), "rate%28x%5B5m%5D%29");
        assert_eq!(urlencode("AZaz09-_.~"), "AZaz09-_.~");
    }

    #[test]
    fn escapes_label_matchers() {
        assert_eq!(label_matcher("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(label_matcher("plain"), "\"plain\"");
    }

    #[test]
    fn decodes_chunked_bodies() {
        let raw = b"5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(raw).unwrap(), b"hello");
    }

    #[test]
    fn parses_http_responses() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        assert_eq!(parse_http_response(raw).unwrap(), b"hi");
        let raw = b"HTTP/1.1 500 Oops\r\nContent-Length: 0\r\n\r\n";
        assert!(parse_http_response(raw).is_err());
    }

    #[test]
    fn matrix_conversion_aligns_and_nulls_non_finite() {
        let result = json!([
            {
                "metric": {"__name__": "x"},
                "values": [[1700000000.0, "1.5"], [1700000015.0, "NaN"]]
            }
        ]);
        let ts = vec![1_700_000_000_000u64, 1_700_000_015_000, 1_700_000_030_000];
        let pts = matrix_to_points(&result, &ts);
        assert_eq!(pts, vec![Some(1.5), None, None]);
    }

    #[test]
    fn matrix_conversion_snaps_misaligned_samples() {
        // Prometheus aligned this sample 200ms off our synthesized axis: an
        // exact lookup would drop it, the half-step snap must keep it.
        let grid = vec![1_700_000_000_000u64, 1_700_000_010_000, 1_700_000_020_000];
        let result = json!([
            {"metric": {}, "values": [[1700000000.2, "7.0"], [1700000010.2, "8.0"]]}
        ]);
        assert_eq!(
            matrix_to_points(&result, &grid),
            vec![Some(7.0), Some(8.0), None]
        );
        // A sample outside the window must not be pulled onto the last grid
        // point (half-step tolerance stops at the grid's edge).
        let far = json!([{"metric": {}, "values": [[1700000030.0, "9.0"]]}]);
        let pts = matrix_to_points(&far, &grid);
        assert_eq!(
            pts,
            vec![None, None, None],
            "samples outside the window are dropped"
        );
    }

    #[test]
    fn synthesized_axis_is_deterministic_and_aligned() {
        let start = 1_700_000_000.0;
        let end = start + 60.0;
        let step = 15u64;
        let a = step_axis(start, end, step);
        assert_eq!(a, step_axis(start, end, step), "deterministic");
        assert_eq!(a.len() as u64, 60 / step + 1);
        assert!(a.windows(2).all(|w| w[1] - w[0] == step * 1000));
        assert_eq!(a[0], (start * 1000.0) as u64);
        assert!(a.last().copied().unwrap() <= (end * 1000.0) as u64 + 1);
    }

    #[test]
    fn global_exprs_cover_every_series_key() {
        let exprs = global_exprs("15s");
        let keys: Vec<&str> = exprs.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, GLOBAL_SERIES.to_vec());
        for (k, e) in &exprs {
            // Rate expressions carry the window; raw gauges do not.
            assert!(e.contains("[15s]") || !e.contains("rate("), "{k}: {e}");
        }
    }

    #[test]
    fn upstream_exprs_cover_every_series_key() {
        let exprs = upstream_exprs("cf-1", "15s");
        let keys: Vec<&str> = exprs.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, UPSTREAM_SERIES.to_vec());
        for (_, e) in &exprs {
            assert!(e.contains("upstream=\"cf-1\""), "{e}");
        }
    }
}
