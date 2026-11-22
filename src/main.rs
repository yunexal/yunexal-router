mod api;
mod config;
mod minecraft;
mod proxy_proto;
mod splice_relay;
mod udp_proxy;
mod xdp;

use api::{run_http_api, ApiState, RouterStats};
use config::RouteConfig;
use minecraft::{read_framed_packet, read_handshake, serve_cached_status, HandshakeError, NextState};
use proxy_proto::{build_proxy_v2_header, local_v4_fallback};
use splice_relay::{splice_bidirectional, tune_tcp_stream};
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use udp_proxy::UdpForwarderManager;
use xdp::{detect_default_interface, XdpShield};

#[derive(Clone)]
struct CachedStatus {
    packet: Vec<u8>,
    fetched_at: Instant,
}

#[derive(Default)]
struct AbuseTracker {
    entries: HashMap<Ipv4Addr, (u32, Instant)>,
}

impl AbuseTracker {
    fn record_invalid(&mut self, ip: Ipv4Addr, threshold: u32) -> bool {
        let now = Instant::now();
        if self.entries.len() > 8192 {
            self.entries
                .retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(60));
        }
        let entry = self.entries.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) > Duration::from_secs(30) {
            *entry = (1, now);
            return false;
        }
        entry.0 += 1;
        entry.1 = now;
        entry.0 >= threshold
    }
}

struct CliArgs {
    mode: String,
    port: u16,
    routes_config: PathBuf,
    routes_watch: bool,
    api_binding: String,
    connection_rate_limit: u32,
    edge_allow: Vec<Ipv4Addr>,
    guard_ports: Vec<u16>,
    interface_override: Option<String>,
}

fn parse_args() -> CliArgs {
    let mut mode = "edge".to_string();
    let mut port = 25565u16;
    let mut routes_config = PathBuf::from("/srv/mc-router/routes.json");
    let mut routes_watch = true;
    let mut api_binding = "127.0.0.1:8085".to_string();
    let mut connection_rate_limit = 30u32;
    let mut edge_allow = Vec::new();
    let mut guard_ports = vec![25565u16, 24454u16];
    let mut interface_override = None;

    for arg in env::args().skip(1) {
        if let Some(v) = arg.strip_prefix("--mode=") {
            mode = v.to_string();
        } else if let Some(v) = arg.strip_prefix("--port=") {
            if let Ok(p) = v.parse() {
                port = p;
            }
        } else if let Some(v) = arg.strip_prefix("--routes-config=") {
            routes_config = PathBuf::from(v);
        } else if arg == "--routes-config-watch" {
            routes_watch = true;
        } else if arg == "--no-routes-watch" {
            routes_watch = false;
        } else if let Some(v) = arg.strip_prefix("--api-binding=") {
            api_binding = v.to_string();
        } else if let Some(v) = arg.strip_prefix("--connection-rate-limit=") {
            if let Ok(r) = v.parse() {
                connection_rate_limit = r;
            }
        } else if let Some(v) = arg.strip_prefix("--edge-allow=") {
            edge_allow = v
                .split(',')
                .filter_map(|s| s.trim().parse::<Ipv4Addr>().ok())
                .collect();
        } else if let Some(v) = arg.strip_prefix("--ports=") {
            let parsed: Vec<u16> = v
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
            if !parsed.is_empty() {
                guard_ports = parsed;
            }
        } else if let Some(v) = arg.strip_prefix("--interface=") {
            interface_override = Some(v.to_string());
        }
    }

    CliArgs {
        mode,
        port,
        routes_config,
        routes_watch,
        api_binding,
        connection_rate_limit,
        edge_allow,
        guard_ports,
        interface_override,
    }
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let started_at = Instant::now();

    if args.mode == "node-guard" {
        run_node_guard_mode(args, started_at).await;
        return;
    }

    let initial_cfg = RouteConfig::load_from_file(&args.routes_config).unwrap_or_else(|e| {
        eprintln!(
            "[router] warning: could not read {}: {e}; using empty config",
            args.routes_config.display()
        );
        RouteConfig::default()
    });

    let config = Arc::new(RwLock::new(initial_cfg.clone()));
    let stats = Arc::new(RouterStats::default());
    let status_cache: Arc<RwLock<HashMap<(String, i32), CachedStatus>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let abuse_tracker = Arc::new(Mutex::new(AbuseTracker::default()));
    let udp_mgr = Arc::new(Mutex::new(UdpForwarderManager::new()));
    let xdp_mode_label = Arc::new(RwLock::new("disabled".to_string()));
    let xdp_shield: Arc<Mutex<Option<XdpShield>>> = Arc::new(Mutex::new(None));

    // Start UDP forwarders & attach XDP shield
    {
        let mut mgr = udp_mgr.lock().await;
        mgr.sync_mappings(&initial_cfg.udp_mappings);
    }
    sync_xdp_state(
        args.port,
        &initial_cfg,
        &xdp_shield,
        &xdp_mode_label,
    )
    .await;

    let udp_metrics = { udp_mgr.lock().await.metrics.clone() };

    let api_state = ApiState {
        config: config.clone(),
        routes_path: args.routes_config.clone(),
        stats: stats.clone(),
        udp_metrics,
        xdp_mode: xdp_mode_label.clone(),
        started_at,
    };
    tokio::spawn(run_http_api(args.api_binding.clone(), api_state));

    // Watch routes.json for dynamic host additions (Pterodactyl / API) & periodically pull XDP stats
    {
        let watch_path = args.routes_config.clone();
        let watch_cfg = config.clone();
        let watch_udp = udp_mgr.clone();
        let watch_xdp = xdp_shield.clone();
        let watch_xdp_mode = xdp_mode_label.clone();
        let watch_stats = stats.clone();
        let do_watch = args.routes_watch;
        let tcp_port = args.port;

        tokio::spawn(async move {
            let mut last_mtime: Option<SystemTime> = file_mtime(&watch_path);
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            let mut ticks = 0u64;
            loop {
                interval.tick().await;
                ticks += 1;

                if do_watch {
                    let cur_mtime = file_mtime(&watch_path);
                    if cur_mtime != last_mtime {
                        if let Ok(new_cfg) = RouteConfig::load_from_file(&watch_path) {
                            last_mtime = cur_mtime;
                            {
                                let mut mgr = watch_udp.lock().await;
                                mgr.sync_mappings(&new_cfg.udp_mappings);
                            }
                            sync_xdp_state(tcp_port, &new_cfg, &watch_xdp, &watch_xdp_mode).await;
                            *watch_cfg.write().await = new_cfg;
                            eprintln!("[router] reloaded {}", watch_path.display());
                        }
                    }
                }

                // Refresh XDP per-CPU stats every ~2 seconds
                if ticks % 4 == 0 {
                    let guard = watch_xdp.lock().await;
                    if let Some(ref shield) = *guard {
                        let snap = shield.read_stats();
                        watch_stats.xdp_passed.store(snap.passed, Ordering::Relaxed);
                        watch_stats
                            .xdp_dropped_blocked
                            .store(snap.dropped_blocked, Ordering::Relaxed);
                        watch_stats
                            .xdp_dropped_syn
                            .store(snap.dropped_syn, Ordering::Relaxed);
                        watch_stats
                            .xdp_dropped_udp
                            .store(snap.dropped_udp, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    let bind_addr = format!("0.0.0.0:{}", args.port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {bind_addr}: {e}"));
    eprintln!(
        "[router] yunexal-router listening on {bind_addr} (rate_limit={} conn/s)",
        args.connection_rate_limit
    );

    let per_ip_conn_window: Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>> =
        Arc::new(Mutex::new(HashMap::new()));

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                let Ok((client_stream, client_addr)) = accept_res else {
                    continue;
                };

                // Simple userspace per-second accept limiter as second defense behind XDP
                if args.connection_rate_limit > 0 {
                    let mut guard = per_ip_conn_window.lock().await;
                    let now = Instant::now();
                    if guard.len() > 8192 {
                        guard.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(2));
                    }
                    let entry = guard.entry(client_addr.ip()).or_insert((0, now));
                    if now.duration_since(entry.1) >= Duration::from_secs(1) {
                        *entry = (1, now);
                    } else {
                        entry.0 += 1;
                        if entry.0 > args.connection_rate_limit {
                            continue;
                        }
                    }
                }

                let cfg = config.clone();
                let st = stats.clone();
                let cache = status_cache.clone();
                let abuse = abuse_tracker.clone();
                let shield = xdp_shield.clone();

                tokio::spawn(async move {
                    handle_client(client_stream, client_addr, cfg, st, cache, abuse, shield).await;
                });
            }
            _ = shutdown_signal() => {
                eprintln!("[router] shutdown signal received; detaching XDP & stopping UDP...");
                udp_mgr.lock().await.stop_all();
                *xdp_shield.lock().await = None;
                break;
            }
        }
    }
}

async fn sync_xdp_state(
    tcp_port: u16,
    cfg: &RouteConfig,
    xdp_slot: &Arc<Mutex<Option<XdpShield>>>,
    mode_label: &Arc<RwLock<String>>,
) {
    let mut guard = xdp_slot.lock().await;
    if !cfg.xdp_enabled {
        *guard = None;
        *mode_label.write().await = "disabled".to_string();
        return;
    }

    if guard.is_none() {
        let iface = cfg
            .xdp_interface
            .clone()
            .or_else(detect_default_interface);
        if let Some(dev) = iface {
            match XdpShield::attach_embedded(&dev) {
                Ok(shield) => {
                    eprintln!("[xdp] attached xdp_shield in mode: {}", shield.mode_label);
                    *mode_label.write().await = shield.mode_label.clone();
                    *guard = Some(shield);
                }
                Err(e) => {
                    eprintln!("[xdp] warning: could not attach on {dev}: {e}");
                    *mode_label.write().await = format!("error: {e}");
                }
            }
        }
    }

    if let Some(ref mut shield) = *guard {
        let mut ports = HashSet::new();
        ports.insert(tcp_port);
        for &p in cfg.udp_mappings.keys() {
            ports.insert(p);
        }
        shield.sync_protected_ports(&ports);
        shield.update_config(cfg.syn_rate_limit_pps, cfg.udp_rate_limit_pps, false);
    }
}

async fn run_node_guard_mode(args: CliArgs, started_at: Instant) {
    if args.edge_allow.is_empty() {
        panic!("--mode=node-guard requires at least one IP in --edge-allow=IP1,IP2");
    }
    let iface = args
        .interface_override
        .or_else(detect_default_interface)
        .expect("could not detect default interface for node-guard");

    let mut shield = XdpShield::attach_embedded(&iface)
        .unwrap_or_else(|e| panic!("failed to attach node-guard XDP on {iface}: {e}"));
    let ports: HashSet<u16> = args.guard_ports.iter().copied().collect();
    shield.sync_protected_ports(&ports);
    shield.set_trusted_edges(&args.edge_allow);
    shield.update_config(1000, 10000, true);

    eprintln!(
        "[node-guard] XDP whitelist active on {} ports={:?} allowed_edges={:?}",
        shield.mode_label, args.guard_ports, args.edge_allow
    );

    let stats = Arc::new(RouterStats::default());
    let mode_label = Arc::new(RwLock::new(format!("node-guard {}", shield.mode_label)));
    let shield_arc = Arc::new(Mutex::new(Some(shield)));

    let api_state = ApiState {
        config: Arc::new(RwLock::new(RouteConfig::default())),
        routes_path: args.routes_config,
        stats: stats.clone(),
        udp_metrics: Arc::new(udp_proxy::UdpMetrics::default()),
        xdp_mode: mode_label,
        started_at,
    };
    tokio::spawn(run_http_api(args.api_binding, api_state));

    let stat_shield = shield_arc.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            let guard = stat_shield.lock().await;
            if let Some(ref s) = *guard {
                let snap = s.read_stats();
                stats.xdp_passed.store(snap.passed, Ordering::Relaxed);
                stats
                    .xdp_dropped_blocked
                    .store(snap.dropped_blocked, Ordering::Relaxed);
            }
        }
    });

    shutdown_signal().await;
    eprintln!("[node-guard] shutting down & detaching XDP...");
    *shield_arc.lock().await = None;
}

async fn handle_client(
    client: TcpStream,
    client_addr: SocketAddr,
    config: Arc<RwLock<RouteConfig>>,
    stats: Arc<RouterStats>,
    status_cache: Arc<RwLock<HashMap<(String, i32), CachedStatus>>>,
    abuse_tracker: Arc<Mutex<AbuseTracker>>,
    xdp_shield: Arc<Mutex<Option<XdpShield>>>,
) {
    tune_tcp_stream(&client);
    stats.total_tcp_connections.fetch_add(1, Ordering::Relaxed);
    stats.active_tcp.fetch_add(1, Ordering::Relaxed);

    let res = process_connection(
        client,
        client_addr,
        config,
        &stats,
        status_cache,
        abuse_tracker,
        xdp_shield,
    )
    .await;

    stats.active_tcp.fetch_sub(1, Ordering::Relaxed);
    if let Err(msg) = res {
        eprintln!("[router] client {client_addr}: {msg}");
    }
}

async fn process_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    config: Arc<RwLock<RouteConfig>>,
    stats: &Arc<RouterStats>,
    status_cache: Arc<RwLock<HashMap<(String, i32), CachedStatus>>>,
    abuse_tracker: Arc<Mutex<AbuseTracker>>,
    xdp_shield: Arc<Mutex<Option<XdpShield>>>,
) -> Result<(), String> {
    let handshake = match read_handshake(&mut client).await {
        Ok(h) => h,
        Err(HandshakeError::LegacyPing(raw)) => {
            // Forward legacy ping to default route cleanly
            let route = {
                let guard = config.read().await;
                guard.default.clone().map(|b| (b, guard.proxy_protocol))
            };
            let Some((backend_addr, use_pp)) = route else {
                return Err("legacy ping with no default backend".to_string());
            };
            let mut backend = connect_backend(&backend_addr).await?;
            let local_dst = client.local_addr().unwrap_or_else(|_| local_v4_fallback(25565));
            if use_pp {
                let hdr = build_proxy_v2_header(client_addr, local_dst);
                backend.write_all(&hdr).await.map_err(|e| e.to_string())?;
            }
            backend.write_all(&raw).await.map_err(|e| e.to_string())?;
            if let Ok((up, down)) = splice_bidirectional(client, backend).await {
                stats.bytes_up.fetch_add(up, Ordering::Relaxed);
                stats.bytes_down.fetch_add(down, Ordering::Relaxed);
            }
            return Ok(());
        }
        Err(HandshakeError::InvalidProtocol(reason)) => {
            stats.total_invalid_handshakes.fetch_add(1, Ordering::Relaxed);
            if let IpAddr::V4(v4) = client_addr.ip() {
                let (thresh, ban_s) = {
                    let g = config.read().await;
                    (g.invalid_conn_ban_threshold, g.invalid_conn_ban_seconds)
                };
                if abuse_tracker.lock().await.record_invalid(v4, thresh) {
                    let mut xdp_guard = xdp_shield.lock().await;
                    if let Some(ref mut shield) = *xdp_guard {
                        shield.block_ipv4(v4, ban_s);
                        eprintln!("[xdp] auto-blocked scanner {v4} for {ban_s}s ({reason})");
                    }
                }
            }
            return Err(format!("invalid handshake: {reason}"));
        }
        Err(HandshakeError::Timeout) => return Err("handshake timeout".to_string()),
        Err(HandshakeError::Io(e)) => return Err(format!("handshake io: {e}")),
    };

    let resolved = {
        let guard = config.read().await;
        guard.resolve(&handshake.server_address)
    };
    let Some(route) = resolved else {
        return Err(format!("no route for host '{}'", handshake.server_address));
    };

    // Fast MOTD / Server List Ping cache if enabled
    if handshake.next_state == NextState::Status && route.status_cache_ttl_ms > 0 {
        let key = (route.backend.clone(), handshake.protocol_version);
        let hit = {
            let guard = status_cache.read().await;
            guard.get(&key).and_then(|c| {
                if c.fetched_at.elapsed() < Duration::from_millis(route.status_cache_ttl_ms) {
                    Some(c.packet.clone())
                } else {
                    None
                }
            })
        };
        if let Some(cached_pkt) = hit {
            stats.total_status_cache_hits.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = serve_cached_status(&mut client, &handshake, &cached_pkt).await {
                return Err(format!("cached status error: {e}"));
            }
            return Ok(());
        }
    }

    let mut backend = connect_backend(&route.backend).await?;
    let local_dst = client.local_addr().unwrap_or_else(|_| local_v4_fallback(handshake.server_port));

    if route.proxy_protocol {
        let hdr = build_proxy_v2_header(client_addr, local_dst);
        backend
            .write_all(&hdr)
            .await
            .map_err(|e| format!("write proxy v2 header: {e}"))?;
    }

    backend
        .write_all(&handshake.raw_prefix)
        .await
        .map_err(|e| format!("write handshake to {}: {e}", route.backend))?;

    // If uncached Status ping with cache enabled: ensure Status Request was sent before waiting for response.
    if handshake.next_state == NextState::Status && route.status_cache_ttl_ms > 0 {
        if handshake.raw_prefix[handshake.handshake_end..].is_empty() {
            let status_req = read_framed_packet(&mut client, 1500, 16)
                .await
                .map_err(|e| format!("read client status request: {e}"))?;
            backend
                .write_all(&status_req)
                .await
                .map_err(|e| format!("forward status request: {e}"))?;
        }

        if let Ok(status_pkt) = read_framed_packet(&mut backend, 2500, 131072).await {
            let key = (route.backend.clone(), handshake.protocol_version);
            {
                let mut guard = status_cache.write().await;
                if guard.len() > 2048 {
                    guard.clear();
                }
                guard.insert(
                    key,
                    CachedStatus {
                        packet: status_pkt.clone(),
                        fetched_at: Instant::now(),
                    },
                );
            }
            if let Err(e) = client.write_all(&status_pkt).await {
                return Err(format!("write fresh status to client: {e}"));
            }
        } else {
            return Err("backend failed to return status response".to_string());
        }
    }

    let (up, down) = splice_bidirectional(client, backend)
        .await
        .map_err(|e| format!("relay error: {e}"))?;
    stats.bytes_up.fetch_add(up, Ordering::Relaxed);
    stats.bytes_down.fetch_add(down, Ordering::Relaxed);
    Ok(())
}

async fn connect_backend(addr: &str) -> Result<TcpStream, String> {
    let stream = tokio::time::timeout(Duration::from_millis(2500), TcpStream::connect(addr))
        .await
        .map_err(|_| format!("connect timeout to {addr}"))?
        .map_err(|e| format!("connect {addr}: {e}"))?;
    tune_tcp_stream(&stream);
    Ok(stream)
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::minecraft::write_varint;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn e2e_proxy_v2_handshake_and_splice_relay() {
        // Mock backend (like Velocity expecting PROXYv2 + MC Handshake + bidirectional payload)
        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();

        let backend_task = tokio::spawn(async move {
            let (mut sock, _) = backend_listener.accept().await.unwrap();
            let mut hdr = [0u8; 28];
            sock.read_exact(&mut hdr).await.unwrap();
            assert_eq!(&hdr[..12], b"\r\n\r\n\0\r\nQUIT\n");
            assert_eq!(hdr[12], 0x21);
            assert_eq!(hdr[13], 0x11);

            let pkt = read_framed_packet(&mut sock, 2000, 1024).await.unwrap();
            assert!(!pkt.is_empty());

            // Echo game bytes after handshake through zero-copy splice
            let mut msg = [0u8; 4];
            sock.read_exact(&mut msg).await.unwrap();
            assert_eq!(&msg, b"PING");
            sock.write_all(b"PONG").await.unwrap();
        });

        let mut cfg_val = RouteConfig::default();
        cfg_val
            .mappings
            .insert("play.yunexal.com".to_string(), backend_addr.to_string());
        cfg_val.proxy_protocol = true;
        cfg_val.status_cache_ttl_ms = 0;
        cfg_val.xdp_enabled = false;
        cfg_val.normalize();

        let router_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let router_addr = router_listener.local_addr().unwrap();

        let cfg = Arc::new(RwLock::new(cfg_val));
        let stats = Arc::new(RouterStats::default());
        let cache = Arc::new(RwLock::new(HashMap::new()));
        let abuse = Arc::new(Mutex::new(AbuseTracker::default()));
        let xdp = Arc::new(Mutex::new(None));

        let router_task = tokio::spawn(async move {
            let (client_sock, peer_addr) = router_listener.accept().await.unwrap();
            handle_client(client_sock, peer_addr, cfg, stats, cache, abuse, xdp).await;
        });

        // Client connects to router, sends MC Handshake for play.yunexal.com + game payload
        let mut client = TcpStream::connect(router_addr).await.unwrap();
        let mut hs_payload = vec![0x00];
        write_varint(&mut hs_payload, 777);
        let host = b"play.yunexal.com";
        write_varint(&mut hs_payload, host.len() as u32);
        hs_payload.extend_from_slice(host);
        hs_payload.extend_from_slice(&25565u16.to_be_bytes());
        write_varint(&mut hs_payload, 2);
        let mut hs = Vec::new();
        write_varint(&mut hs, hs_payload.len() as u32);
        hs.extend_from_slice(&hs_payload);

        client.write_all(&hs).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        client.write_all(b"PING").await.unwrap();

        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"PONG");
        drop(client);

        backend_task.await.unwrap();
        router_task.await.unwrap();
    }
}
