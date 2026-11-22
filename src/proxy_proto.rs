use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// HAProxy PROXY protocol v2 magic signature (12 bytes).
const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Normalizes IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to native IPv4 when applicable.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// Builds a binary HAProxy PROXY Protocol v2 header (TCP4 or TCP6).
pub fn build_proxy_v2_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let src_ip = normalize_ip(src.ip());
    let dst_ip = normalize_ip(dst.ip());

    let mut buf = Vec::with_capacity(52);
    buf.extend_from_slice(&V2_SIGNATURE);
    buf.push(0x21); // version 2 (0x20) | command PROXY (0x01)

    match (src_ip, dst_ip) {
        (IpAddr::V4(s4), IpAddr::V4(d4)) => {
            buf.push(0x11); // AF_INET | STREAM
            buf.extend_from_slice(&12u16.to_be_bytes());
            buf.extend_from_slice(&s4.octets());
            buf.extend_from_slice(&d4.octets());
            buf.extend_from_slice(&src.port().to_be_bytes());
            buf.extend_from_slice(&dst.port().to_be_bytes());
        }
        (s, d) => {
            let s6 = match s {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            let d6 = match d {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            buf.push(0x21); // AF_INET6 | STREAM
            buf.extend_from_slice(&36u16.to_be_bytes());
            buf.extend_from_slice(&s6.octets());
            buf.extend_from_slice(&d6.octets());
            buf.extend_from_slice(&src.port().to_be_bytes());
            buf.extend_from_slice(&dst.port().to_be_bytes());
        }
    }

    buf
}

pub fn local_v4_fallback(dst_port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), dst_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_tcp4_proxy_v2_header_cleanly() {
        let src: SocketAddr = "198.51.100.42:45123".parse().unwrap();
        let dst: SocketAddr = "203.0.113.10:25565".parse().unwrap();
        let hdr = build_proxy_v2_header(src, dst);
        assert_eq!(hdr.len(), 28);
        assert_eq!(&hdr[..12], &V2_SIGNATURE);
        assert_eq!(hdr[12], 0x21);
        assert_eq!(hdr[13], 0x11);
        assert_eq!(u16::from_be_bytes([hdr[14], hdr[15]]), 12);
        assert_eq!(&hdr[16..20], &[198, 51, 100, 42]);
        assert_eq!(&hdr[20..24], &[203, 0, 113, 10]);
        assert_eq!(u16::from_be_bytes([hdr[24], hdr[25]]), 45123);
        assert_eq!(u16::from_be_bytes([hdr[26], hdr[27]]), 25565);
    }
}
