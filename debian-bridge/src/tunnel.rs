use crate::crypto::{handshake_server, Psa1Reader, Psa1Writer};
use std::collections::HashMap;
use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

pub const TYPE_OPEN: u8 = 0x01;
pub const TYPE_DATA: u8 = 0x02;
pub const TYPE_CLOSE: u8 = 0x03;
pub const TYPE_PING: u8 = 0x04;
pub const TYPE_PONG: u8 = 0x05;
const HEADER_LEN: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelFrame {
    Open { channel_id: u32 },
    Data { channel_id: u32, payload: Vec<u8> },
    Close { channel_id: u32 },
    Ping,
    Pong,
}

impl TunnelFrame {
    pub fn encode(&self) -> Vec<u8> {
        let (kind, channel_id, payload): (u8, u32, &[u8]) = match self {
            TunnelFrame::Open { channel_id } => (TYPE_OPEN, *channel_id, &[]),
            TunnelFrame::Data {
                channel_id,
                payload,
            } => (TYPE_DATA, *channel_id, payload.as_slice()),
            TunnelFrame::Close { channel_id } => (TYPE_CLOSE, *channel_id, &[]),
            TunnelFrame::Ping => (TYPE_PING, 0, &[]),
            TunnelFrame::Pong => (TYPE_PONG, 0, &[]),
        };
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.push(kind);
        out.extend_from_slice(&channel_id.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TunnelFrame too short",
            ));
        }
        let kind = bytes[0];
        let channel_id = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let payload = &bytes[HEADER_LEN..];

        match kind {
            TYPE_OPEN => Ok(TunnelFrame::Open { channel_id }),
            TYPE_DATA => Ok(TunnelFrame::Data {
                channel_id,
                payload: payload.to_vec(),
            }),
            TYPE_CLOSE => Ok(TunnelFrame::Close { channel_id }),
            TYPE_PING => Ok(TunnelFrame::Ping),
            TYPE_PONG => Ok(TunnelFrame::Pong),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown TunnelFrame type: {other}"),
            )),
        }
    }
}

pub enum ChannelEvent {
    Data(Vec<u8>),
    Closed,
}

pub struct ActiveTunnel {
    pub id: u64,
    writer: Mutex<Psa1Writer<TcpStream>>,
    raw_stream: TcpStream,
    channels: Mutex<HashMap<u32, mpsc::Sender<ChannelEvent>>>,
    next_channel_id: AtomicU32,
}

impl ActiveTunnel {
    fn new(id: u64, write_stream: TcpStream, send_key: &[u8; 32]) -> io::Result<Self> {
        let raw_stream = write_stream.try_clone()?;
        Ok(Self {
            id,
            writer: Mutex::new(Psa1Writer::new(write_stream, send_key)),
            raw_stream,
            channels: Mutex::new(HashMap::new()),
            next_channel_id: AtomicU32::new(1),
        })
    }

    pub fn send_frame(&self, frame: &TunnelFrame) -> io::Result<()> {
        let mut writer = self.writer.lock().unwrap();
        writer.write_record(&frame.encode())
    }

    pub fn open_channel(&self) -> io::Result<(u32, mpsc::Receiver<ChannelEvent>)> {
        let channel_id = self.next_channel_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        self.channels.lock().unwrap().insert(channel_id, tx);
        if let Err(e) = self.send_frame(&TunnelFrame::Open { channel_id }) {
            self.channels.lock().unwrap().remove(&channel_id);
            return Err(e);
        }
        Ok((channel_id, rx))
    }

    pub fn close_channel(&self, channel_id: u32) {
        self.channels.lock().unwrap().remove(&channel_id);
        let _ = self.send_frame(&TunnelFrame::Close { channel_id });
    }

    fn deliver(&self, channel_id: u32, event: ChannelEvent) {
        let sender = self.channels.lock().unwrap().get(&channel_id).cloned();
        if let Some(tx) = sender {
            let _ = tx.send(event);
        }
    }

    fn fail_all_channels(&self) {
        let mut map = self.channels.lock().unwrap();
        for (_, tx) in map.drain() {
            let _ = tx.send(ChannelEvent::Closed);
        }
    }

    pub fn shutdown(&self) {
        let _ = self.raw_stream.shutdown(Shutdown::Both);
        self.fail_all_channels();
    }
}

pub struct BridgeHub {
    active: Mutex<Option<Arc<ActiveTunnel>>>,
    next_tunnel_id: AtomicU64,
}

impl BridgeHub {
    pub fn new() -> Self {
        Self {
            active: Mutex::new(None),
            next_tunnel_id: AtomicU64::new(1),
        }
    }

    pub fn current_tunnel(&self) -> Option<Arc<ActiveTunnel>> {
        self.active.lock().unwrap().clone()
    }

    fn set_tunnel(&self, tunnel: Arc<ActiveTunnel>) {
        let previous = self.active.lock().unwrap().replace(tunnel);
        if let Some(old) = previous {
            eprintln!("[bridge] Replacing previous Android tunnel #{}", old.id);
            old.shutdown();
        }
    }

    fn clear_if_matches(&self, tunnel_id: u64) {
        let mut guard = self.active.lock().unwrap();
        if guard.as_ref().map(|t| t.id) == Some(tunnel_id) {
            if let Some(t) = guard.take() {
                t.fail_all_channels();
            }
        }
    }
}

pub fn run_tcp_listener(bind_addr: String, psk: [u8; 32], hub: Arc<BridgeHub>) -> io::Result<()> {
    let listener = TcpListener::bind(&bind_addr)?;
    eprintln!("[bridge] Listening for Android PSA1 tunnel on TCP {bind_addr}");

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let hub_clone = Arc::clone(&hub);
                thread::spawn(move || handle_android_connection(stream, psk, hub_clone));
            }
            Err(e) => {
                eprintln!("[bridge] TCP accept error: {e}");
                thread::sleep(Duration::from_millis(200));
            }
        }
    }
    Ok(())
}

fn handle_android_connection(mut stream: TcpStream, psk: [u8; 32], hub: Arc<BridgeHub>) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let (send_key, recv_key) = match handshake_server(&mut stream, &psk) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("[bridge] PSA1 handshake failed from {peer}: {e}");
            return;
        }
    };

    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));

    let write_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bridge] Failed to clone TCP stream: {e}");
            return;
        }
    };

    let tunnel_id = hub.next_tunnel_id.fetch_add(1, Ordering::Relaxed);
    let tunnel = match ActiveTunnel::new(tunnel_id, write_stream, &send_key) {
        Ok(t) => Arc::new(t),
        Err(e) => {
            eprintln!("[bridge] Failed to initialize tunnel: {e}");
            return;
        }
    };

    hub.set_tunnel(Arc::clone(&tunnel));
    eprintln!("[bridge] Android SSH Agent authenticated & connected (tunnel #{tunnel_id} from {peer})");

    let mut reader = Psa1Reader::new(stream, &recv_key);
    loop {
        match reader.read_record() {
            Ok(raw) => match TunnelFrame::decode(&raw) {
                Ok(TunnelFrame::Ping) => {
                    if tunnel.send_frame(&TunnelFrame::Pong).is_err() {
                        break;
                    }
                }
                Ok(TunnelFrame::Pong) => {}
                Ok(TunnelFrame::Data {
                    channel_id,
                    payload,
                }) => {
                    tunnel.deliver(channel_id, ChannelEvent::Data(payload));
                }
                Ok(TunnelFrame::Close { channel_id }) => {
                    tunnel.deliver(channel_id, ChannelEvent::Closed);
                    tunnel.channels.lock().unwrap().remove(&channel_id);
                }
                Ok(TunnelFrame::Open { .. }) => {}
                Err(e) => {
                    eprintln!("[bridge] Malformed tunnel frame: {e}");
                    break;
                }
            },
            Err(e) => {
                eprintln!("[bridge] Android tunnel #{tunnel_id} disconnected: {e}");
                break;
            }
        }
    }

    hub.clear_if_matches(tunnel_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_frame_roundtrip() {
        let frames = vec![
            TunnelFrame::Open { channel_id: 42 },
            TunnelFrame::Data {
                channel_id: 7,
                payload: vec![11],
            },
            TunnelFrame::Close { channel_id: 42 },
            TunnelFrame::Ping,
            TunnelFrame::Pong,
        ];
        for frame in frames {
            let encoded = frame.encode();
            let decoded = TunnelFrame::decode(&encoded).unwrap();
            assert_eq!(frame, decoded);
        }
    }
}
