use aya::maps::{Array, HashMap, MapData, PerCpuArray};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use std::collections::HashSet;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Default)]
pub struct XdpStatsSnapshot {
    pub passed: u64,
    pub dropped_blocked: u64,
    pub dropped_syn: u64,
    pub dropped_udp: u64,
}

pub struct XdpShield {
    ebpf: Ebpf,
    pub mode_label: String,
    active_ports: HashSet<u16>,
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

impl XdpShield {
    /// Loads embedded XDP eBPF bytecode and attaches to `interface` (DRV_MODE first, fallback SKB_MODE).
    pub fn attach_embedded(interface: &str) -> Result<Self, String> {
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/xdp_shield.o"
        )))
        .map_err(|e| format!("Ebpf::load failed: {e}"))?;

        let prog: &mut Xdp = ebpf
            .program_mut("xdp_shield")
            .ok_or_else(|| "missing xdp_shield program".to_string())?
            .try_into()
            .map_err(|e| format!("program try_into Xdp failed: {e}"))?;

        prog.load()
            .map_err(|e| format!("XDP load/verify failed: {e}"))?;

        let mode_label = match prog.attach(interface, XdpFlags::DRV_MODE) {
            Ok(_) => format!("DRV ({interface})"),
            Err(drv_err) => {
                eprintln!("[xdp] DRV_MODE on {interface} unavailable ({drv_err}); falling back to SKB_MODE");
                prog.attach(interface, XdpFlags::SKB_MODE)
                    .map_err(|e| format!("XDP SKB_MODE attach failed on {interface}: {e}"))?;
                format!("SKB ({interface})")
            }
        };

        Ok(Self {
            ebpf,
            mode_label,
            active_ports: HashSet::new(),
        })
    }

    pub fn update_config(&mut self, max_syn_pps: u32, max_udp_pps: u32, whitelist_only: bool) {
        if let Some(map) = self.ebpf.map_mut("config_map") {
            if let Ok(mut arr) = Array::<_, u32>::try_from(map) {
                let _ = arr.set(0, max_syn_pps.max(5), 0);
                let _ = arr.set(1, max_udp_pps.max(20), 0);
                let _ = arr.set(2, if whitelist_only { 1u32 } else { 0u32 }, 0);
            }
        }
    }

    pub fn set_trusted_edges(&mut self, edges: &[Ipv4Addr]) {
        let Some(map) = self.ebpf.map_mut("trusted_edges") else {
            return;
        };
        if let Ok(mut hm) = HashMap::<_, u32, u8>::try_from(map) {
            let existing: Vec<u32> = hm.keys().filter_map(|k| k.ok()).collect();
            for k in existing {
                let _ = hm.remove(&k);
            }
            for ip in edges {
                let key = u32::from_ne_bytes(ip.octets());
                let _ = hm.insert(key, 1u8, 0);
            }
        }
    }

    pub fn sync_protected_ports(&mut self, desired: &HashSet<u16>) {
        let Some(map) = self.ebpf.map_mut("protected_ports") else {
            return;
        };
        let Ok(mut hm) = HashMap::<_, u16, u8>::try_from(map) else {
            return;
        };

        let removed: Vec<u16> = self.active_ports.difference(desired).copied().collect();
        for p in removed {
            let _ = hm.remove(&p);
        }
        for &p in desired {
            if !self.active_ports.contains(&p) {
                let _ = hm.insert(p, 1u8, 0);
            }
        }
        self.active_ports = desired.clone();
    }

    pub fn block_ipv4(&mut self, ip: Ipv4Addr, duration_secs: u64) {
        if ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified() {
            return;
        }
        let Some(map) = self.ebpf.map_mut("blocked_ips") else {
            return;
        };
        if let Ok(mut hm) = HashMap::<_, u32, u64>::try_from(map) {
            // Kernel iphdr->saddr holds raw big-endian octets in memory; from_ne_bytes matches byte-for-byte.
            let key = u32::from_ne_bytes(ip.octets());
            let expiry = monotonic_ns().saturating_add(duration_secs.saturating_mul(1_000_000_000));
            let _ = hm.insert(key, expiry, 0);
        }
    }

    pub fn read_stats(&self) -> XdpStatsSnapshot {
        let Some(map) = self.ebpf.map("stats_map") else {
            return XdpStatsSnapshot::default();
        };
        let Ok(arr) = PerCpuArray::<&MapData, u64>::try_from(map) else {
            return XdpStatsSnapshot::default();
        };

        let sum_idx = |idx: u32| -> u64 {
            arr.get(&idx, 0)
                .map(|vals| vals.iter().copied().sum())
                .unwrap_or(0)
        };

        XdpStatsSnapshot {
            passed: sum_idx(0),
            dropped_blocked: sum_idx(1),
            dropped_syn: sum_idx(2),
            dropped_udp: sum_idx(3),
        }
    }
}

/// Picks the primary default-route network interface name from `/proc/net/route`.
pub fn detect_default_interface() -> Option<String> {
    let contents = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in contents.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3 && cols[1] == "00000000" {
            return Some(cols[0].to_string());
        }
    }
    None
}
