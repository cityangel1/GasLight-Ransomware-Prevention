// Dashboard telemetry feed.
//
// Connect a browser dashboard to ws://127.0.0.1:<port> to receive a live
// stream of JSON-serialized events (each one already includes the current
// system risk score — see main.rs's detector loop for how it's attached).
//
// KNOWN LIMITATION: this server only writes to clients, it never reads
// incoming frames. That means it won't respond to WebSocket pings/pongs or
// notice a client-initiated close until the next failed write (broken
// pipe). Fine for a lightweight live dashboard feed; a production version should
// spawn a reader half per connection too.

use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use tungstenite::{accept, Message};

pub type SubscriberRegistry = Arc<Mutex<Vec<Sender<String>>>>;

pub fn new_registry() -> SubscriberRegistry {
    Arc::new(Mutex::new(Vec::new()))
}

/// Sends `message` to every currently-connected dashboard client. Dead
/// subscribers (send failed, meaning the client thread has exited) are
/// pruned automatically.
pub fn broadcast(registry: &SubscriberRegistry, message: &str) {
    if let Ok(mut subs) = registry.lock() {
        subs.retain(|s| s.send(message.to_string()).is_ok());
    }
}

pub fn start(registry: SubscriberRegistry, port: u16) {
    let addr = format!("127.0.0.1:{port}");
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            crate::utils::logger::critical(&format!("[dashboard] failed to bind {addr}: {e}"));
            return;
        }
    };
    crate::utils::logger::info(&format!(
        "[dashboard] telemetry feed listening on ws://{addr}"
    ));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let registry = registry.clone();
                thread::spawn(move || handle_client(stream, registry));
            }
            Err(e) => {
                crate::utils::logger::warn(&format!("[dashboard] connection error: {e}"));
            }
        }
    }
}

fn handle_client(stream: TcpStream, registry: SubscriberRegistry) {
    let mut ws = match accept(stream) {
        Ok(ws) => ws,
        Err(e) => {
            crate::utils::logger::warn(&format!("[dashboard] handshake failed: {e}"));
            return;
        }
    };

    let (tx, rx) = channel::<String>();
    if let Ok(mut subs) = registry.lock() {
        subs.push(tx);
    }
    crate::utils::logger::info("[dashboard] client connected");

    for message in rx {
        if ws.send(Message::Text(message)).is_err() {
            break;
        }
    }
    crate::utils::logger::info("[dashboard] client disconnected");
}
