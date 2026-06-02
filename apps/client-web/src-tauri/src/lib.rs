//! ESTATES desktop shell — wraps the Vite/React/SVG client in a native window.
//! The game logic runs in the web layer (the pure engine in-browser); this is a
//! thin WebView host. Keys never leave the client.
//!
//! It ALSO embeds an always-on relay on 127.0.0.1:8788 so the desktop app needs
//! zero setup. The relay is an untrusted, opaque per-channel fan-out. It is a
//! CONSTANT KEEP-ALIVE STREAM: GET /subscribe/<ch> stays open and every new
//! payload is PUSHED to it instantly (Server-Sent Events) — so two windows (you
//! + a simulated player) sync in milliseconds. POST /publish/<ch> appends +
//! pushes; GET /history/<ch> returns the full ordered log (a heal backstop if a
//! stream frame is ever missed). CORS is open so the webview may call it. The
//! relay never sees plaintext or game logic.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

struct Channel {
    log: Vec<String>,
    clients: Vec<Arc<Mutex<TcpStream>>>, // open SSE connections, pushed to on publish
}
type Channels = Arc<Mutex<HashMap<String, Channel>>>;

const CORS: &str = "Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
Access-Control-Allow-Headers: *\r\n";

/// Start the embedded relay. If the port is already taken (an external relay is
/// running), silently reuse it — the client just talks to that one instead.
pub fn start_relay(port: u16) {
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(_) => return,
    };
    let channels: Channels = Arc::new(Mutex::new(HashMap::new()));

    // Heartbeat keeps SSE connections alive and prunes any that died.
    {
        let channels = channels.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(15));
            let mut map = channels.lock().unwrap();
            for ch in map.values_mut() {
                ch.clients.retain(|c| c.lock().map(|mut s| s.write_all(b": keepalive\n\n").and_then(|_| s.flush()).is_ok()).unwrap_or(false));
            }
        });
    }

    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(s) = stream {
                let ch = channels.clone();
                thread::spawn(move || { let _ = handle(s, ch); });
            }
        }
    });
}

fn handle(mut s: TcpStream, channels: Channels) -> std::io::Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(p) = find(&buf, b"\r\n\r\n") { break p; }
        let n = s.read(&mut tmp)?;
        if n == 0 { return Ok(()); }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 * 1024 { break buf.len(); }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("").split('?').next().unwrap_or("");

    let mut content_len = 0usize;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = buf[(header_end + 4).min(buf.len())..].to_vec();
    while body.len() < content_len {
        let n = s.read(&mut tmp)?;
        if n == 0 { break; }
        body.extend_from_slice(&tmp[..n]);
    }

    let seg: Vec<&str> = path.split('/').filter(|x| !x.is_empty()).collect();

    if method == "OPTIONS" {
        return write_resp(&mut s, "204 No Content", "text/plain", b"");
    }

    // POST /publish/<channel> — append the opaque hex payload AND push it live to
    // every open subscriber (instant), pruning any dead connection.
    if method == "POST" && seg.len() == 2 && seg[0] == "publish" {
        let hex = String::from_utf8_lossy(&body).trim().to_string();
        if !hex.is_empty() {
            let frame = format!("data: {hex}\n\n");
            let mut map = channels.lock().unwrap();
            let ch = map.entry(seg[1].to_string()).or_insert_with(|| Channel { log: Vec::new(), clients: Vec::new() });
            ch.log.push(hex);
            ch.clients.retain(|c| c.lock().map(|mut st| st.write_all(frame.as_bytes()).and_then(|_| st.flush()).is_ok()).unwrap_or(false));
        }
        return write_resp(&mut s, "204 No Content", "text/plain", b"");
    }

    // GET /history/<channel> — full ordered log, newline-separated hex (heal).
    if method == "GET" && seg.len() == 2 && seg[0] == "history" {
        let map = channels.lock().unwrap();
        let body = map.get(seg[1]).map(|c| c.log.join("\n")).unwrap_or_default();
        return write_resp(&mut s, "200 OK", "text/plain", body.as_bytes());
    }

    // GET /subscribe/<channel> — keep-alive SSE: replay history, then stay open
    // and receive every future payload pushed by /publish.
    if method == "GET" && seg.len() == 2 && seg[0] == "subscribe" {
        let headers = format!("HTTP/1.1 200 OK\r\n{CORS}Content-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n");
        s.write_all(headers.as_bytes())?;
        // Replay history + register this connection, atomically vs. publishes.
        {
            let mut map = channels.lock().unwrap();
            let ch = map.entry(seg[1].to_string()).or_insert_with(|| Channel { log: Vec::new(), clients: Vec::new() });
            for hex in &ch.log { s.write_all(format!("data: {hex}\n\n").as_bytes())?; }
            s.flush()?;
            let writer = Arc::new(Mutex::new(s.try_clone()?));
            ch.clients.push(writer);
        }
        // Block until the client disconnects (read returns 0/err); publishes write
        // to the registered clone meanwhile. Then we simply return (heartbeat prunes).
        let mut sink = [0u8; 1024];
        loop {
            match s.read(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        return Ok(());
    }

    write_resp(&mut s, "404 Not Found", "text/plain", b"")
}

fn write_resp(s: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\n{CORS}Content-Type: {content_type}\r\nCache-Control: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes())?;
    s.write_all(body)?;
    s.flush()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    start_relay(8788); // always-on embedded relay: zero setup, instant local sync

    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running the ESTATES desktop application");
}
