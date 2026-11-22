use crate::config::{normalize_hostname, RouteConfig};
use crate::udp_proxy::UdpMetrics;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

#[derive(Default)]
pub struct RouterStats {
    pub active_tcp: AtomicU64,
    pub total_tcp_connections: AtomicU64,
    pub total_status_cache_hits: AtomicU64,
    pub total_invalid_handshakes: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub xdp_passed: AtomicU64,
    pub xdp_dropped_blocked: AtomicU64,
    pub xdp_dropped_syn: AtomicU64,
    pub xdp_dropped_udp: AtomicU64,
}

#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<RwLock<RouteConfig>>,
    pub routes_path: PathBuf,
    pub stats: Arc<RouterStats>,
    pub udp_metrics: Arc<UdpMetrics>,
    pub xdp_mode: Arc<RwLock<String>>,
    pub started_at: Instant,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpsertRouteBody {
    server_address: String,
    backend: String,
    proxy_protocol: Option<bool>,
}

#[derive(Serialize)]
struct HealthBody<'a> {
    status: &'static str,
    uptime_secs: u64,
    xdp_mode: &'a str,
    active_tcp: u64,
    active_udp: u64,
}

pub async fn run_http_api(bind_addr: String, state: ApiState) {
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[api] failed to bind {bind_addr}: {e}");
            return;
        }
    };
    eprintln!("[api] listening on http://{bind_addr}");

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let st = state.clone();
        tokio::spawn(async move {
            let _ = handle_http(stream, st).await;
        });
    }
}

async fn handle_http(mut stream: TcpStream, state: ApiState) -> std::io::Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0);
    if n == 0 {
        return Ok(());
    }

    let raw = String::from_utf8_lossy(&buf[..n]);
    let mut parts = raw.split("\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("");
    let first_line = head.lines().next().unwrap_or("");
    let mut tokens = first_line.split_whitespace();
    let method = tokens.next().unwrap_or("GET");
    let path = tokens.next().unwrap_or("/");

    let (code, resp_body) = match (method, path) {
        ("GET", "/health") => {
            let mode = state.xdp_mode.read().await.clone();
            let h = HealthBody {
                status: "ok",
                uptime_secs: state.started_at.elapsed().as_secs(),
                xdp_mode: &mode,
                active_tcp: state.stats.active_tcp.load(Ordering::Relaxed),
                active_udp: state.udp_metrics.active_sessions.load(Ordering::Relaxed),
            };
            ("200 OK", serde_json::to_string_pretty(&h).unwrap_or_default())
        }
        ("GET", "/metrics") => {
            let m = serde_json::json!({
                "uptime_secs": state.started_at.elapsed().as_secs(),
                "active_tcp": state.stats.active_tcp.load(Ordering::Relaxed),
                "active_udp_sessions": state.udp_metrics.active_sessions.load(Ordering::Relaxed),
                "udp_packets_in": state.udp_metrics.packets_in.load(Ordering::Relaxed),
                "udp_packets_out": state.udp_metrics.packets_out.load(Ordering::Relaxed),
                "total_tcp_connections": state.stats.total_tcp_connections.load(Ordering::Relaxed),
                "total_status_cache_hits": state.stats.total_status_cache_hits.load(Ordering::Relaxed),
                "total_invalid_handshakes": state.stats.total_invalid_handshakes.load(Ordering::Relaxed),
                "bytes_up": state.stats.bytes_up.load(Ordering::Relaxed),
                "bytes_down": state.stats.bytes_down.load(Ordering::Relaxed),
                "xdp_mode": state.xdp_mode.read().await.as_str(),
                "xdp_passed": state.stats.xdp_passed.load(Ordering::Relaxed),
                "xdp_dropped_blocked": state.stats.xdp_dropped_blocked.load(Ordering::Relaxed),
                "xdp_dropped_syn": state.stats.xdp_dropped_syn.load(Ordering::Relaxed),
                "xdp_dropped_udp": state.stats.xdp_dropped_udp.load(Ordering::Relaxed),
            });
            ("200 OK", serde_json::to_string_pretty(&m).unwrap_or_default())
        }
        ("GET", "/routes") => {
            let cfg = state.config.read().await;
            (
                "200 OK",
                serde_json::to_string_pretty(&*cfg).unwrap_or_default(),
            )
        }
        ("POST", "/routes") => match serde_json::from_str::<UpsertRouteBody>(body.trim()) {
            Ok(req) => {
                let mut cfg = state.config.write().await;
                let host = normalize_hostname(&req.server_address);
                cfg.mappings.insert(host.clone(), req.backend);
                if let Some(pp) = req.proxy_protocol {
                    cfg.route_options.entry(host).or_default().proxy_protocol = Some(pp);
                }
                let _ = cfg.save_to_file(&state.routes_path);
                ("200 OK", r#"{"ok":true}"#.to_string())
            }
            Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
        },
        ("DELETE", p) if p.starts_with("/routes/") => {
            let host = normalize_hostname(p.trim_start_matches("/routes/"));
            let mut cfg = state.config.write().await;
            let existed = cfg.mappings.remove(&host).is_some();
            let _ = cfg.save_to_file(&state.routes_path);
            ("200 OK", format!(r#"{{"removed":{existed}}}"#))
        }
        _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
    };

    let response = format!(
        "HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
        resp_body.len()
    );
    stream.write_all(response.as_bytes()).await
}
