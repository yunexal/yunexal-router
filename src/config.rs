use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerRouteOptions {
    #[serde(default)]
    pub proxy_protocol: Option<bool>,
    #[serde(default)]
    pub status_cache_ttl_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteConfig {
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub mappings: HashMap<String, String>,
    #[serde(default)]
    pub udp_mappings: HashMap<u16, String>,
    #[serde(default)]
    pub route_options: HashMap<String, PerRouteOptions>,
    #[serde(default)]
    pub proxy_protocol: bool,
    #[serde(default = "default_status_cache_ttl_ms")]
    pub status_cache_ttl_ms: u64,
    #[serde(default = "default_true")]
    pub xdp_enabled: bool,
    #[serde(default)]
    pub xdp_interface: Option<String>,
    #[serde(default = "default_syn_pps")]
    pub syn_rate_limit_pps: u32,
    #[serde(default = "default_udp_pps")]
    pub udp_rate_limit_pps: u32,
    #[serde(default = "default_invalid_ban_threshold")]
    pub invalid_conn_ban_threshold: u32,
    #[serde(default = "default_invalid_ban_seconds")]
    pub invalid_conn_ban_seconds: u64,
}

fn default_true() -> bool {
    true
}

fn default_status_cache_ttl_ms() -> u64 {
    2500
}

fn default_syn_pps() -> u32 {
    60
}

fn default_udp_pps() -> u32 {
    800
}

fn default_invalid_ban_threshold() -> u32 {
    12
}

fn default_invalid_ban_seconds() -> u64 {
    120
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            default: None,
            mappings: HashMap::new(),
            udp_mappings: HashMap::new(),
            route_options: HashMap::new(),
            proxy_protocol: false,
            status_cache_ttl_ms: default_status_cache_ttl_ms(),
            xdp_enabled: true,
            xdp_interface: None,
            syn_rate_limit_pps: default_syn_pps(),
            udp_rate_limit_pps: default_udp_pps(),
            invalid_conn_ban_threshold: default_invalid_ban_threshold(),
            invalid_conn_ban_seconds: default_invalid_ban_seconds(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    pub backend: String,
    pub proxy_protocol: bool,
    pub status_cache_ttl_ms: u64,
}

impl RouteConfig {
    pub fn load_from_file(path: &Path) -> io::Result<Self> {
        let raw = fs::read_to_string(path)?;
        let mut cfg: RouteConfig = serde_json::from_str(&raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        cfg.normalize();
        Ok(cfg)
    }

    pub fn save_to_file(&self, path: &Path) -> io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        let serialized = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&tmp, serialized + "\n")?;
        fs::rename(tmp, path)?;
        Ok(())
    }

    pub fn normalize(&mut self) {
        let mut normalized = HashMap::with_capacity(self.mappings.len());
        for (k, v) in &self.mappings {
            normalized.insert(normalize_hostname(k), v.clone());
        }
        self.mappings = normalized;

        let mut norm_opts = HashMap::with_capacity(self.route_options.len());
        for (k, v) in &self.route_options {
            norm_opts.insert(normalize_hostname(k), v.clone());
        }
        self.route_options = norm_opts;
    }

    pub fn resolve(&self, raw_server_address: &str) -> Option<ResolvedRoute> {
        let host = normalize_hostname(raw_server_address);

        let (matched_key, backend) = if let Some(b) = self.mappings.get(&host) {
            (Some(host.as_str()), b.as_str())
        } else if let Some((wk, b)) = self.find_wildcard(&host) {
            (Some(wk), b)
        } else if let Some(ref def) = self.default {
            (Some("default"), def.as_str())
        } else {
            return None;
        };

        let opts = matched_key.and_then(|k| self.route_options.get(k));
        let proxy_protocol = opts
            .and_then(|o| o.proxy_protocol)
            .unwrap_or(self.proxy_protocol);
        let status_cache_ttl_ms = opts
            .and_then(|o| o.status_cache_ttl_ms)
            .unwrap_or(self.status_cache_ttl_ms);

        Some(ResolvedRoute {
            backend: backend.to_string(),
            proxy_protocol,
            status_cache_ttl_ms,
        })
    }

    fn find_wildcard<'a>(&'a self, host: &str) -> Option<(&'a str, &'a str)> {
        let mut best: Option<(&str, &str)> = None;
        for (pattern, backend) in &self.mappings {
            if let Some(suffix) = pattern.strip_prefix("*.") {
                if host == suffix
                    || (host.len() > suffix.len()
                        && host.ends_with(suffix)
                        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
                {
                    if best.map(|(b, _)| pattern.len() > b.len()).unwrap_or(true) {
                        best = Some((pattern.as_str(), backend.as_str()));
                    }
                }
            }
        }
        best
    }
}

pub fn normalize_hostname(raw: &str) -> String {
    // Strip Forge / NeoForge / Velocity null-separated markers (e.g. "play.yunexal.com\0FML3\0")
    let base = raw.split('\0').next().unwrap_or(raw);
    let base = if let Some(idx) = base.rfind(':') {
        // Ignore IPv6 brackets unless port follows ']'
        if !base.contains('[') || base[idx..].contains(']') {
            base
        } else {
            &base[..idx]
        }
    } else {
        base
    };
    base.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_forge_and_wildcard_and_default() {
        let mut cfg = RouteConfig::default();
        cfg.default = Some("192.0.2.10:25565".to_string());
        cfg.mappings
            .insert("PLAY.EXAMPLE.COM.".to_string(), "192.0.2.10:25565".to_string());
        cfg.mappings
            .insert("*.client.example.com".to_string(), "192.0.2.20:25565".to_string());
        cfg.route_options.insert(
            "*.client.example.com".to_string(),
            PerRouteOptions {
                proxy_protocol: Some(true),
                status_cache_ttl_ms: Some(0),
            },
        );
        cfg.normalize();

        let exact = cfg.resolve("Play.Example.Com\0FML3\0").unwrap();
        assert_eq!(exact.backend, "192.0.2.10:25565");
        assert!(!exact.proxy_protocol);

        let wild = cfg.resolve("Alpha.Client.Example.Com.").unwrap();
        assert_eq!(wild.backend, "192.0.2.20:25565");
        assert!(wild.proxy_protocol);
        assert_eq!(wild.status_cache_ttl_ms, 0);

        let def = cfg.resolve("unknown.example.org").unwrap();
        assert_eq!(def.backend, "192.0.2.10:25565");
    }
}
