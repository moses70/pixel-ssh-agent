#[cfg(unix)]
use crate::tunnel::{BridgeHub, ChannelEvent, TunnelFrame};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
const MAX_AGENT_MSG_LEN: usize = 256 * 1024;
#[cfg(unix)]
const SSH_AGENT_FAILURE_MSG: &[u8] = &[0, 0, 0, 1, 5];
#[cfg(unix)]
const SIGN_RESPONSE_TIMEOUT: Duration = Duration::from_secs(65);

#[cfg(unix)]
pub fn bind_unix_agent_socket(socket_path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Never unlink a socket that another live bridge instance is actively serving.
    if UnixStream::connect(socket_path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!(
                "Unix socket {} is already in use by a running bridge",
                socket_path.display()
            ),
        ));
    }

    if fs::symlink_metadata(socket_path).is_ok() {
        fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    eprintln!("[bridge] SSH_AUTH_SOCK ready at {}", socket_path.display());
    Ok(listener)
}

#[cfg(unix)]
pub fn serve_unix_agent(listener: UnixListener, hub: Arc<BridgeHub>) -> io::Result<()> {
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let hub_clone = Arc::clone(&hub);
                thread::spawn(move || handle_ssh_client(stream, hub_clone));
            }
            Err(e) => {
                eprintln!("[bridge] Unix socket accept error: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn handle_ssh_client(mut stream: UnixStream, hub: Arc<BridgeHub>) {
    let tunnel = match hub.current_tunnel() {
        Some(t) => t,
        None => {
            // Read one request if present and return SSH_AGENT_FAILURE cleanly so ssh falls back.
            if let Ok(Some(_)) = read_ssh_agent_message(&mut stream) {
                let _ = stream.write_all(SSH_AGENT_FAILURE_MSG);
                let _ = stream.flush();
            }
            return;
        }
    };

    let (channel_id, rx) = match tunnel.open_channel() {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("[bridge] Failed to open tunnel channel: {e}");
            let _ = stream.write_all(SSH_AGENT_FAILURE_MSG);
            return;
        }
    };

    struct ChannelGuard<'a> {
        tunnel: &'a crate::tunnel::ActiveTunnel,
        channel_id: u32,
    }
    impl Drop for ChannelGuard<'_> {
        fn drop(&mut self) {
            self.tunnel.close_channel(self.channel_id);
        }
    }
    let _guard = ChannelGuard {
        tunnel: &tunnel,
        channel_id,
    };

    loop {
        let msg = match read_ssh_agent_message(&mut stream) {
            Ok(Some(m)) => m,
            Ok(None) => break, // clean EOF from ssh client
            Err(e) => {
                eprintln!("[bridge] Unix client read error: {e}");
                break;
            }
        };

        if let Err(e) = tunnel.send_frame(&TunnelFrame::Data {
            channel_id,
            payload: msg,
        }) {
            eprintln!("[bridge] Tunnel send error on channel #{channel_id}: {e}");
            let _ = stream.write_all(SSH_AGENT_FAILURE_MSG);
            break;
        }

        match rx.recv_timeout(SIGN_RESPONSE_TIMEOUT) {
            Ok(ChannelEvent::Data(response)) => {
                if write_ssh_agent_message(&mut stream, &response).is_err() {
                    break;
                }
            }
            Ok(ChannelEvent::Closed) => {
                let _ = stream.write_all(SSH_AGENT_FAILURE_MSG);
                break;
            }
            Err(_) => {
                eprintln!(
                    "[bridge] Timed out waiting for Android response on channel #{channel_id}"
                );
                let _ = stream.write_all(SSH_AGENT_FAILURE_MSG);
                break;
            }
        }
    }
}

#[cfg(unix)]
fn read_ssh_agent_message(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_AGENT_MSG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid SSH agent message length: {len}"),
        ));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(Some(payload))
}

#[cfg(unix)]
fn write_ssh_agent_message(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::env;
    use std::process;

    #[test]
    fn bind_refuses_to_unlink_active_socket_but_cleans_stale_socket() {
        let dir = env::temp_dir().join(format!("psa-unix-test-{}", process::id()));
        let sock = dir.join("agent.sock");
        let _ = fs::remove_dir_all(&dir);

        // First bind succeeds.
        let first = bind_unix_agent_socket(&sock).expect("initial bind should succeed");

        // Second bind while first listener is alive must fail with AddrInUse and keep socket intact.
        let err = bind_unix_agent_socket(&sock).expect_err("second bind should fail");
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        assert!(
            UnixStream::connect(&sock).is_ok(),
            "first listener socket must remain connectable"
        );

        // After dropping the first listener, the stale socket file should be replaced cleanly.
        drop(first);
        let second = bind_unix_agent_socket(&sock).expect("re-bind over stale socket should work");
        assert!(UnixStream::connect(&sock).is_ok());

        drop(second);
        let _ = fs::remove_dir_all(&dir);
    }
}
