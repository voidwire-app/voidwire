//! In-process `iroh-relay-v2` test relay for offline integration and e2e tests.
//!
//! Speaks `iroh-relay-v2` over HTTP WebSocket (`GET /relay`) plus `GET /ping`
//! and records every relayed datagram payload and HTTP probe hit so tests can
//! verify:
//! 1. Direct-UDP-blocked peers pair and deliver URLs via the relay.
//! 2. Relayed bytes are strictly QUIC/TLS 1.3 + HPKE ciphertext (no plaintext
//!    URL bytes ever appear in relayed frames).
//! 3. `captive_portal_check = false` suppresses `GET /generate_204` probes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// iroh-relay-v2 FrameType tags (postcard varint u32 < 128 = 1 byte)
const FT_SERVER_CHALLENGE: u8 = 0;
const FT_CLIENT_AUTH: u8 = 1;
const FT_SERVER_CONFIRMS_AUTH: u8 = 2;
const FT_CLIENT_TO_RELAY_DATAGRAM: u8 = 4;
const FT_CLIENT_TO_RELAY_DATAGRAM_BATCH: u8 = 5;
const FT_RELAY_TO_CLIENT_DATAGRAM: u8 = 6;
const FT_RELAY_TO_CLIENT_DATAGRAM_BATCH: u8 = 7;
const FT_ENDPOINT_GONE: u8 = 8;
const FT_PING: u8 = 9;
const FT_PONG: u8 = 10;

struct RelayInner {
    peers: Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<Vec<u8>>>>,
    relayed: Mutex<Vec<Vec<u8>>>,
    ping_hits: AtomicUsize,
    captive_portal_hits: AtomicUsize,
}

/// A running in-process test relay.
pub struct TestRelay {
    addr: SocketAddr,
    inner: Arc<RelayInner>,
    stop_tx: Option<oneshot::Sender<()>>,
    _rt: Option<tokio::runtime::Runtime>,
}

impl TestRelay {
    /// Start a local test relay on `127.0.0.1:0` with its own background runtime.
    pub fn start() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("test relay runtime");
        let (addr, inner, stop_tx) = rt.block_on(Self::bind_inner());
        #[cfg(any(test, feature = "test-util"))]
        crate::pairing::register_test_relay_port(addr.port());
        Self {
            addr,
            inner,
            stop_tx: Some(stop_tx),
            _rt: Some(rt),
        }
    }

    async fn bind_inner() -> (SocketAddr, Arc<RelayInner>, oneshot::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test relay");
        let addr = listener.local_addr().expect("local_addr");
        let inner = Arc::new(RelayInner {
            peers: Mutex::new(HashMap::new()),
            relayed: Mutex::new(Vec::new()),
            ping_hits: AtomicUsize::new(0),
            captive_portal_hits: AtomicUsize::new(0),
        });
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        let inner2 = inner.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    acc = listener.accept() => {
                        let Ok((stream, _)) = acc else { break };
                        let _ = stream.set_nodelay(true);
                        let st = inner2.clone();
                        tokio::spawn(async move {
                            let _ = handle_conn(stream, st).await;
                        });
                    }
                }
            }
        });
        (addr, inner, stop_tx)
    }

    /// The `http://127.0.0.1:<port>` URL for `RelayMode::Custom`.
    pub fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    /// Socket address of the relay listener.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every raw datagram payload forwarded through the relay so far.
    pub fn relayed_datagrams(&self) -> Vec<Vec<u8>> {
        self.inner.relayed.lock().unwrap().clone()
    }

    /// Number of `GET /ping` probe requests received.
    pub fn ping_hits(&self) -> usize {
        self.inner.ping_hits.load(Ordering::SeqCst)
    }

    /// Number of `GET /generate_204` captive-portal requests received.
    pub fn captive_portal_hits(&self) -> usize {
        self.inner.captive_portal_hits.load(Ordering::SeqCst)
    }

    /// Whether `id` is currently connected to the relay.
    pub fn has_peer(&self, id: &crate::ids::DeviceId) -> bool {
        self.inner.peers.lock().unwrap().contains_key(id.as_bytes())
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        #[cfg(any(test, feature = "test-util"))]
        crate::pairing::unregister_test_relay_port(self.addr.port());
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
    }
}

async fn handle_conn(mut stream: TcpStream, inner: Arc<RelayInner>) -> std::io::Result<()> {
    let mut hdr = Vec::with_capacity(1024);
    let mut b = [0u8; 1];
    while !hdr.ends_with(b"\r\n\r\n") {
        if stream.read(&mut b).await? == 0 {
            return Ok(());
        }
        hdr.push(b[0]);
        if hdr.len() > 8192 {
            return Ok(());
        }
    }
    let req = String::from_utf8_lossy(&hdr);
    let first_line = req.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("");

    if path.starts_with("/ping") {
        inner.ping_hits.fetch_add(1, Ordering::SeqCst);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(());
    }
    if path.starts_with("/generate_204") {
        inner.captive_portal_hits.fetch_add(1, Ordering::SeqCst);
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(());
    }
    if !path.starts_with("/relay") {
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(());
    }

    let mut ws_key = None;
    for line in req.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("sec-websocket-key") {
                ws_key = Some(v.trim().to_string());
            }
        }
    }
    let Some(ws_key) = ws_key else {
        return Ok(());
    };
    let accept = ws_accept(&ws_key);
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         Sec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n"
    );
    stream.write_all(resp.as_bytes()).await?;

    // 1. Send ServerChallenge: [FT_SERVER_CHALLENGE, 16-byte challenge]
    let mut challenge = [0u8; 17];
    challenge[0] = FT_SERVER_CHALLENGE;
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut challenge[1..]);
    write_ws_binary(&mut stream, &challenge).await?;

    // 2. Read ClientAuth: [FT_CLIENT_AUTH, 32-byte PublicKey, ...]
    let Some((opcode, auth)) = read_ws_frame(&mut stream).await? else {
        return Ok(());
    };
    if opcode != 0x02 || auth.len() < 1 + 32 || auth[0] != FT_CLIENT_AUTH {
        return Ok(());
    }
    let mut client_id = [0u8; 32];
    client_id.copy_from_slice(&auth[1..33]);

    // 3. Send ServerConfirmsAuth: [FT_SERVER_CONFIRMS_AUTH]
    write_ws_binary(&mut stream, &[FT_SERVER_CONFIRMS_AUTH]).await?;

    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    inner.peers.lock().unwrap().insert(client_id, tx);

    loop {
        tokio::select! {
            out = rx.recv() => {
                let Some(frame) = out else { break };
                if write_ws_binary(&mut stream, &frame).await.is_err() {
                    break;
                }
            }
            inc = read_ws_frame(&mut stream) => {
                let Ok(Some((opcode, payload))) = inc else { break };
                match opcode {
                    0x02 => {
                        if payload.is_empty() {
                            continue;
                        }
                        match payload[0] {
                            FT_CLIENT_TO_RELAY_DATAGRAM if payload.len() > 1 + 32 => {
                                let mut dst = [0u8; 32];
                                dst.copy_from_slice(&payload[1..33]);
                                let rest = &payload[33..];
                                inner.relayed.lock().unwrap().push(rest[1..].to_vec());
                                let mut fwd = Vec::with_capacity(1 + 32 + rest.len());
                                fwd.push(FT_RELAY_TO_CLIENT_DATAGRAM);
                                fwd.extend_from_slice(&client_id);
                                fwd.extend_from_slice(rest);
                                if let Some(peer_tx) = inner.peers.lock().unwrap().get(&dst) {
                                    let _ = peer_tx.send(fwd);
                                }
                            }
                            FT_CLIENT_TO_RELAY_DATAGRAM_BATCH if payload.len() >= 1 + 32 + 3 => {
                                let mut dst = [0u8; 32];
                                dst.copy_from_slice(&payload[1..33]);
                                let rest = &payload[33..];
                                inner.relayed.lock().unwrap().push(rest[3..].to_vec());
                                let mut fwd = Vec::with_capacity(1 + 32 + rest.len());
                                fwd.push(FT_RELAY_TO_CLIENT_DATAGRAM_BATCH);
                                fwd.extend_from_slice(&client_id);
                                fwd.extend_from_slice(rest);
                                if let Some(peer_tx) = inner.peers.lock().unwrap().get(&dst) {
                                    let _ = peer_tx.send(fwd);
                                }
                            }
                            FT_PING if payload.len() >= 9 => {
                                let mut pong = [0u8; 9];
                                pong[0] = FT_PONG;
                                pong[1..9].copy_from_slice(&payload[1..9]);
                                if write_ws_binary(&mut stream, &pong).await.is_err() {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    0x09 => {
                        // WebSocket Ping -> Pong
                        if write_ws_frame(&mut stream, 0x0A, &payload).await.is_err() {
                            break;
                        }
                    }
                    0x08 => break, // WebSocket Close
                    _ => {}
                }
            }
        }
    }

    // Remove and notify peers
    let mut peers = inner.peers.lock().unwrap();
    peers.remove(&client_id);
    let mut gone = Vec::with_capacity(33);
    gone.push(FT_ENDPOINT_GONE);
    gone.extend_from_slice(&client_id);
    for peer_tx in peers.values() {
        let _ = peer_tx.send(gone.clone());
    }
    Ok(())
}

async fn write_ws_binary(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    write_ws_frame(stream, 0x02, payload).await
}

async fn write_ws_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut hdr = Vec::with_capacity(10);
    hdr.push(0x80 | (opcode & 0x0F));
    if payload.len() < 126 {
        hdr.push(payload.len() as u8);
    } else if payload.len() <= 65535 {
        hdr.push(126);
        hdr.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        hdr.push(127);
        hdr.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    stream.write_all(&hdr).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

async fn read_ws_frame(stream: &mut TcpStream) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut h = [0u8; 2];
    if stream.read_exact(&mut h).await.is_err() {
        return Ok(None);
    }
    let opcode = h[0] & 0x0F;
    let masked = (h[1] & 0x80) != 0;
    let mut len = (h[1] & 0x7F) as usize;
    if len == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as usize;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        stream.read_exact(&mut ext).await?;
        len = u64::from_be_bytes(ext) as usize;
    }
    if len > 256 * 1024 {
        return Ok(None);
    }
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask).await?;
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    if masked {
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Ok(Some((opcode, data)))
}

fn ws_accept(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + WS_GUID.len());
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(WS_GUID.as_bytes());
    let digest = sha1(&input);
    base64_encode(&digest)
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 0x3F) as usize] as char);
        out.push(T[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(T[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6455_accept_vector() {
        assert_eq!(
            ws_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
