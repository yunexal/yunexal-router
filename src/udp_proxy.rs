use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const UDP_BUF_SIZE: usize = 4096;

#[derive(Default)]
pub struct UdpMetrics {
    pub active_sessions: AtomicU64,
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}

struct UdpSession {
    upstream: Arc<UdpSocket>,
    last_active_epoch_sec: AtomicU64,
}

pub struct UdpForwarderManager {
    active_ports: HashMap<u16, (String, Arc<AtomicBool>)>,
    pub metrics: Arc<UdpMetrics>,
    start: Instant,
}

impl UdpForwarderManager {
    pub fn new() -> Self {
        Self {
            active_ports: HashMap::new(),
            metrics: Arc::new(UdpMetrics::default()),
            start: Instant::now(),
        }
    }

    pub fn sync_mappings(&mut self, desired: &HashMap<u16, String>) {
        // Stop listeners removed or pointing to a changed backend
        let to_remove: Vec<u16> = self
            .active_ports
            .iter()
            .filter_map(|(&port, (backend, _))| match desired.get(&port) {
                Some(new_b) if new_b == backend => None,
                _ => Some(port),
            })
            .collect();

        for port in to_remove {
            if let Some((_, stop_flag)) = self.active_ports.remove(&port) {
                stop_flag.store(true, Ordering::Relaxed);
                eprintln!("[udp] stopped forwarder on :{port}");
            }
        }

        // Start newly added listeners
        for (&port, backend) in desired {
            if self.active_ports.contains_key(&port) {
                continue;
            }
            let stop_flag = Arc::new(AtomicBool::new(false));
            let flag_clone = stop_flag.clone();
            let backend_clone = backend.clone();
            let metrics = self.metrics.clone();
            let start = self.start;

            tokio::spawn(async move {
                if let Err(e) = run_udp_listener(port, backend_clone, flag_clone, metrics, start).await {
                    eprintln!("[udp] listener :{port} error: {e}");
                }
            });

            self.active_ports.insert(port, (backend.clone(), stop_flag));
        }
    }

    pub fn stop_all(&mut self) {
        for (_, (_, flag)) in self.active_ports.drain() {
            flag.store(true, Ordering::Relaxed);
        }
    }
}

fn tune_udp_buffers(sock: &UdpSocket) {
    let fd = sock.as_raw_fd();
    let val: libc::c_int = 4 * 1024 * 1024;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

async fn run_udp_listener(
    listen_port: u16,
    backend_addr: String,
    stop: Arc<AtomicBool>,
    metrics: Arc<UdpMetrics>,
    start: Instant,
) -> io::Result<()> {
    let bind_addr: SocketAddr = format!("0.0.0.0:{listen_port}").parse().unwrap();
    let downstream = Arc::new(UdpSocket::bind(bind_addr).await?);
    tune_udp_buffers(&downstream);
    eprintln!("[udp] forwarding :{listen_port}/udp -> {backend_addr}");

    let sessions: Arc<RwLock<HashMap<SocketAddr, Arc<UdpSession>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Session reaper task
    let reaper_sessions = sessions.clone();
    let reaper_stop = stop.clone();
    let reaper_metrics = metrics.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        while !reaper_stop.load(Ordering::Relaxed) {
            interval.tick().await;
            let now_s = start.elapsed().as_secs();
            let mut guard = reaper_sessions.write().await;
            guard.retain(|_, s| {
                let last = s.last_active_epoch_sec.load(Ordering::Relaxed);
                now_s.saturating_sub(last) < UDP_IDLE_TIMEOUT.as_secs()
            });
            reaper_metrics
                .active_sessions
                .store(guard.len() as u64, Ordering::Relaxed);
        }
    });

    let mut buf = vec![0u8; UDP_BUF_SIZE];
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let res = tokio::time::timeout(Duration::from_secs(1), downstream.recv_from(&mut buf)).await;
        let (len, client_addr) = match res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                eprintln!("[udp] :{listen_port} recv error: {e}");
                continue;
            }
            Err(_) => continue,
        };

        metrics.packets_in.fetch_add(1, Ordering::Relaxed);
        metrics.bytes_in.fetch_add(len as u64, Ordering::Relaxed);

        let now_s = start.elapsed().as_secs();
        let existing = {
            let guard = sessions.read().await;
            guard.get(&client_addr).cloned()
        };

        let session = match existing {
            Some(s) => {
                s.last_active_epoch_sec.store(now_s, Ordering::Relaxed);
                s
            }
            None => {
                let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                tune_udp_buffers(&sock);
                if let Err(e) = sock.connect(&backend_addr).await {
                    eprintln!("[udp] failed connecting upstream {backend_addr}: {e}");
                    continue;
                }
                let s = Arc::new(UdpSession {
                    upstream: sock.clone(),
                    last_active_epoch_sec: AtomicU64::new(now_s),
                });
                {
                    let mut guard = sessions.write().await;
                    guard.insert(client_addr, s.clone());
                    metrics
                        .active_sessions
                        .store(guard.len() as u64, Ordering::Relaxed);
                }

                // Spawn backend -> client reader
                let ds = downstream.clone();
                let s_weak = Arc::downgrade(&s);
                let m = metrics.clone();
                let st = stop.clone();
                tokio::spawn(async move {
                    let mut up_buf = vec![0u8; UDP_BUF_SIZE];
                    while !st.load(Ordering::Relaxed) {
                        let Some(sess) = s_weak.upgrade() else {
                            break;
                        };
                        match tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut up_buf)).await {
                            Ok(Ok(n)) if n > 0 => {
                                sess.last_active_epoch_sec
                                    .store(start.elapsed().as_secs(), Ordering::Relaxed);
                                if ds.send_to(&up_buf[..n], client_addr).await.is_ok() {
                                    m.packets_out.fetch_add(1, Ordering::Relaxed);
                                    m.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                                }
                            }
                            Ok(Ok(_)) => continue,
                            Ok(Err(_)) => break,
                            Err(_) => continue,
                        }
                    }
                });
                s
            }
        };

        let _ = session.upstream.send(&buf[..len]).await;
    }

    Ok(())
}
