use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const MAX_HANDSHAKE_BUFFER: usize = 4096;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(3000);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextState {
    Status,
    Login,
    Transfer,
    Unknown(i32),
}

#[derive(Debug, Clone)]
pub struct HandshakeInfo {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: NextState,
    /// Complete raw bytes already read from client (handshake + any trailing coalesced bytes like Login Start / Status Request).
    pub raw_prefix: Vec<u8>,
    /// Exact byte offset where the Handshake packet ends inside `raw_prefix`.
    pub handshake_end: usize,
}

#[derive(Debug)]
pub enum HandshakeError {
    Io(io::Error),
    Timeout,
    InvalidProtocol(&'static str),
    LegacyPing(Vec<u8>),
}

pub async fn read_handshake(stream: &mut TcpStream) -> Result<HandshakeInfo, HandshakeError> {
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 512];

    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(HandshakeError::Timeout);
        }
        let n = match timeout(deadline - now, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                return Err(HandshakeError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF before handshake",
                )));
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(HandshakeError::Io(e)),
            Err(_) => return Err(HandshakeError::Timeout),
        };

        if buf.len() + n > MAX_HANDSHAKE_BUFFER {
            return Err(HandshakeError::InvalidProtocol("handshake exceeded 4096 bytes"));
        }
        buf.extend_from_slice(&chunk[..n]);

        // Legacy pre-1.7 ping (0xFE) should not trigger anti-scanner auto-ban
        if buf[0] == 0xFE {
            return Err(HandshakeError::LegacyPing(buf));
        }
        // Quick reject obvious HTTP/TLS/ASCII junk on first byte
        if buf[0] == b'G' || buf[0] == b'P' || buf[0] == b'H' || buf[0] == 0x16 {
            return Err(HandshakeError::InvalidProtocol("non-minecraft protocol signature"));
        }

        match try_parse_handshake(&buf) {
            ParseAttempt::Complete(mut info) => {
                info.raw_prefix = buf;
                return Ok(info);
            }
            ParseAttempt::NeedMore => continue,
            ParseAttempt::Invalid(msg) => return Err(HandshakeError::InvalidProtocol(msg)),
        }
    }
}

enum ParseAttempt {
    Complete(HandshakeInfo),
    NeedMore,
    Invalid(&'static str),
}

fn try_parse_handshake(data: &[u8]) -> ParseAttempt {
    let (pkt_len, len_bytes) = match read_varint(data) {
        VarIntRead::Ok(val, sz) => (val, sz),
        VarIntRead::NeedMore => return ParseAttempt::NeedMore,
        VarIntRead::Invalid => return ParseAttempt::Invalid("malformed packet length varint"),
    };

    if pkt_len <= 0 || pkt_len as usize > MAX_HANDSHAKE_BUFFER {
        return ParseAttempt::Invalid("invalid handshake packet length");
    }

    let total_needed = len_bytes + (pkt_len as usize);
    if data.len() < total_needed {
        return ParseAttempt::NeedMore;
    }

    let payload = &data[len_bytes..total_needed];
    let mut cursor = 0usize;

    let packet_id = match read_varint(&payload[cursor..]) {
        VarIntRead::Ok(id, sz) => {
            cursor += sz;
            id
        }
        _ => return ParseAttempt::Invalid("malformed packet id"),
    };
    if packet_id != 0x00 {
        return ParseAttempt::Invalid("expected handshake packet id 0x00");
    }

    let protocol_version = match read_varint(&payload[cursor..]) {
        VarIntRead::Ok(v, sz) => {
            cursor += sz;
            v
        }
        _ => return ParseAttempt::Invalid("malformed protocol version"),
    };

    let str_len = match read_varint(&payload[cursor..]) {
        VarIntRead::Ok(l, sz) if (0..=1024).contains(&l) => {
            cursor += sz;
            l as usize
        }
        _ => return ParseAttempt::Invalid("invalid server address length"),
    };

    if payload.len() < cursor + str_len + 3 {
        return ParseAttempt::Invalid("truncated handshake payload");
    }

    let server_address = match std::str::from_utf8(&payload[cursor..cursor + str_len]) {
        Ok(s) => s.to_string(),
        Err(_) => return ParseAttempt::Invalid("non-utf8 server address"),
    };
    cursor += str_len;

    let server_port = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
    cursor += 2;

    let next_state_val = match read_varint(&payload[cursor..]) {
        VarIntRead::Ok(s, _) => s,
        _ => return ParseAttempt::Invalid("malformed next_state"),
    };

    let next_state = match next_state_val {
        1 => NextState::Status,
        2 => NextState::Login,
        3 => NextState::Transfer,
        other => NextState::Unknown(other),
    };

    ParseAttempt::Complete(HandshakeInfo {
        protocol_version,
        server_address,
        server_port,
        next_state,
        raw_prefix: Vec::new(),
        handshake_end: total_needed,
    })
}

enum VarIntRead {
    Ok(i32, usize),
    NeedMore,
    Invalid,
}

fn read_varint(bytes: &[u8]) -> VarIntRead {
    let mut num = 0i32;
    for (idx, &b) in bytes.iter().enumerate() {
        if idx >= 5 {
            return VarIntRead::Invalid;
        }
        num |= ((b & 0x7F) as i32) << (7 * idx);
        if (b & 0x80) == 0 {
            return VarIntRead::Ok(num, idx + 1);
        }
    }
    VarIntRead::NeedMore
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn write_varint(out: &mut Vec<u8>, mut val: u32) {
    loop {
        let mut temp = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            temp |= 0x80;
        }
        out.push(temp);
        if val == 0 {
            break;
        }
    }
}

/// Reads full MC framed packet `[VarInt length][VarInt id][payload...]`, returning raw framed packet bytes.
pub async fn read_framed_packet(stream: &mut TcpStream, timeout_ms: u64, max_len: usize) -> io::Result<Vec<u8>> {
    let fut = async {
        let mut len_bytes = Vec::with_capacity(5);
        let mut b = [0u8; 1];
        let pkt_len: usize;
        loop {
            stream.read_exact(&mut b).await?;
            len_bytes.push(b[0]);
            match read_varint(&len_bytes) {
                VarIntRead::Ok(v, _) => {
                    if v <= 0 || v as usize > max_len {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "packet length out of bounds"));
                    }
                    pkt_len = v as usize;
                    break;
                }
                VarIntRead::NeedMore => continue,
                VarIntRead::Invalid => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid varint length"));
                }
            }
        }
        let mut out = Vec::with_capacity(len_bytes.len() + pkt_len);
        out.extend_from_slice(&len_bytes);
        out.resize(len_bytes.len() + pkt_len, 0);
        stream.read_exact(&mut out[len_bytes.len()..]).await?;
        Ok(out)
    };
    timeout(Duration::from_millis(timeout_ms), fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "packet read timeout"))?
}

/// Handles a cached Server List Ping locally after Status Response was served from cache.
pub async fn serve_cached_status(
    client: &mut TcpStream,
    handshake: &HandshakeInfo,
    cached_status_packet: &[u8],
) -> io::Result<()> {
    // Client may have sent Status Request (0x01, 0x00) already inside `raw_prefix[handshake_end..]`
    let trailing = &handshake.raw_prefix[handshake.handshake_end..];
    if trailing.is_empty() {
        let _ = read_framed_packet(client, 1500, 16).await?;
    }
    client.write_all(cached_status_packet).await?;

    // Optional Ping packet [0x09, 0x01, 8-byte payload] -> respond with identical Pong
    if let Ok(ping_pkt) = read_framed_packet(client, 1500, 32).await {
        client.write_all(&ping_pkt).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_handshake_with_trailing_login() {
        let mut payload = vec![0x00]; // packet id
        write_varint(&mut payload, 777); // 26.3 protocol
        let host = b"play.yunexal.com\0FML3\0";
        write_varint(&mut payload, host.len() as u32);
        payload.extend_from_slice(host);
        payload.extend_from_slice(&25565u16.to_be_bytes());
        write_varint(&mut payload, 2); // Login

        let mut framed = Vec::new();
        write_varint(&mut framed, payload.len() as u32);
        framed.extend_from_slice(&payload);
        let handshake_end = framed.len();
        framed.extend_from_slice(&[0x05, 0x00, 0xAA, 0xBB, 0xCC]); // coalesced trailing bytes

        match try_parse_handshake(&framed) {
            ParseAttempt::Complete(info) => {
                assert_eq!(info.protocol_version, 777);
                assert_eq!(info.server_address, "play.yunexal.com\0FML3\0");
                assert_eq!(info.server_port, 25565);
                assert_eq!(info.next_state, NextState::Login);
                assert_eq!(info.handshake_end, handshake_end);
            }
            _ => panic!("expected complete handshake"),
        }
    }
}
