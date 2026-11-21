mod config;
mod crypto;
mod tunnel;
mod unix_agent;

use config::BridgeConfig;
use std::env;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::thread;
use tunnel::BridgeHub;

fn print_usage() {
    eprintln!(
        "pixel-ssh-agent-bridge — Encrypted SSH-Agent Bridge for Pixel Linux Terminal (AVF)\n\n\
         USAGE:\n\
           pixel-ssh-agent-bridge init      [--port <PORT>] [--psk <64-HEX>] [--socket <PATH>] [--config <PATH>]\n\
           pixel-ssh-agent-bridge run       [--config <PATH>] [--bind <ADDR:PORT>] [--socket <PATH>]\n\
           pixel-ssh-agent-bridge print-env [--config <PATH>]\n\
           pixel-ssh-agent-bridge test-live [--port <PORT>] [--psk <64-HEX>] [--config <PATH>]\n"
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        process::exit(2);
    }

    let res = match args[0].as_str() {
        "init" => cmd_init(&args[1..]),
        "run" => cmd_run(&args[1..]),
        "print-env" => cmd_print_env(&args[1..]),
        "test-live" => cmd_test_live(&args[1..]),
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("Unknown subcommand: {other}\n");
            print_usage();
            process::exit(2);
        }
    };

    if let Err(e) = res {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

fn cmd_init(args: &[String]) -> std::io::Result<()> {
    let mut port: u16 = 22999;
    let mut psk_arg: Option<String> = None;
    let mut socket_path = BridgeConfig::default_socket_path();
    let mut config_path = BridgeConfig::default_config_path();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                let raw = args.get(i).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "--port requires a value")
                })?;
                port = raw.parse().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid port number")
                })?;
            }
            "--psk" => {
                i += 1;
                psk_arg = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "--psk requires a value",
                            )
                        })?
                        .clone(),
                );
            }
            "--socket" => {
                i += 1;
                let raw = args.get(i).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--socket requires a value",
                    )
                })?;
                socket_path = PathBuf::from(raw);
            }
            "--config" => {
                i += 1;
                let raw = args.get(i).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--config requires a value",
                    )
                })?;
                config_path = PathBuf::from(raw);
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Unknown option: {other}"),
                ));
            }
        }
        i += 1;
    }

    let psk = match psk_arg {
        Some(hex_str) => BridgeConfig::parse_psk_hex(&hex_str)?,
        None => BridgeConfig::generate_random_psk(),
    };

    let cfg = BridgeConfig {
        bind_addr: format!("0.0.0.0:{port}"),
        socket_path,
        psk,
    };
    cfg.save(&config_path)?;

    println!("Saved config to: {}", config_path.display());
    println!("Bind address:    {}", cfg.bind_addr);
    println!("SSH_AUTH_SOCK:   {}", cfg.socket_path.display());
    println!("Pairing PSK:     {}", hex::encode(cfg.psk));
    println!();
    println!("Next steps:");
    println!("  1. Enable port forwarding for port {port} in Pixel Linux Terminal settings.");
    println!("  2. Start the bridge:   pixel-ssh-agent-bridge run");
    println!(
        "  3. Export in shell:    export SSH_AUTH_SOCK=\"{}\"",
        cfg.socket_path.display()
    );
    Ok(())
}

fn cmd_print_env(args: &[String]) -> std::io::Result<()> {
    let config_path = parse_config_path(args)?;
    let cfg = BridgeConfig::load(&config_path)?;
    println!("export SSH_AUTH_SOCK=\"{}\"", cfg.socket_path.display());
    Ok(())
}

fn cmd_run(args: &[String]) -> std::io::Result<()> {
    let mut config_path = BridgeConfig::default_config_path();
    let mut bind_override: Option<String> = None;
    let mut socket_override: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                config_path = PathBuf::from(args.get(i).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--config requires a value",
                    )
                })?);
            }
            "--bind" => {
                i += 1;
                bind_override = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "--bind requires a value",
                            )
                        })?
                        .clone(),
                );
            }
            "--socket" => {
                i += 1;
                socket_override = Some(PathBuf::from(args.get(i).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--socket requires a value",
                    )
                })?));
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Unknown option: {other}"),
                ));
            }
        }
        i += 1;
    }

    let mut cfg = BridgeConfig::load(&config_path)?;
    if let Some(bind) = bind_override {
        cfg.bind_addr = bind;
    }
    if let Some(sock) = socket_override {
        cfg.socket_path = sock;
    }

    let hub = Arc::new(BridgeHub::new());
    let tcp_hub = Arc::clone(&hub);
    let bind_addr = cfg.bind_addr.clone();
    let psk = cfg.psk;

    thread::spawn(move || {
        if let Err(e) = tunnel::run_tcp_listener(bind_addr, psk, tcp_hub) {
            eprintln!("[bridge] Fatal TCP listener error: {e}");
            process::exit(1);
        }
    });

    #[cfg(unix)]
    {
        unix_agent::run_unix_agent_server(&cfg.socket_path, hub)
    }
    #[cfg(not(unix))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Unix domain SSH_AUTH_SOCK server requires Linux/Unix (run inside Pixel Debian VM)",
        ))
    }
}

fn parse_config_path(args: &[String]) -> std::io::Result<PathBuf> {
    let mut config_path = BridgeConfig::default_config_path();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--config" {
            i += 1;
            let raw = args.get(i).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "--config requires a value",
                )
            })?;
            config_path = PathBuf::from(raw);
        }
        i += 1;
    }
    Ok(config_path)
}

/// Cross-platform live integration test against a running Android app (emulator or device).
/// Listens on TCP, performs the PSA1 handshake, tests Ping/Pong, REQUEST_IDENTITIES, and SIGN_REQUEST.
fn cmd_test_live(args: &[String]) -> std::io::Result<()> {
    use crate::crypto::{handshake_server, Psa1Reader, Psa1Writer};
    use crate::tunnel::TunnelFrame;
    use sha2::{Digest, Sha256};
    use std::io;
    use std::net::TcpListener;
    use std::time::Duration;

    let mut port: u16 = 22999;
    let mut psk_arg: Option<String> = None;
    let mut config_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                port = args
                    .get(i)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "--port requires a value")
                    })?
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid port"))?;
            }
            "--psk" => {
                i += 1;
                psk_arg = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "--psk requires a value")
                        })?
                        .clone(),
                );
            }
            "--config" => {
                i += 1;
                config_path = Some(PathBuf::from(args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--config requires a value")
                })?));
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unknown option: {other}"),
                ));
            }
        }
        i += 1;
    }

    let psk = match (psk_arg, config_path) {
        (Some(raw), _) => BridgeConfig::parse_psk_hex(&raw)?,
        (None, Some(path)) => BridgeConfig::load(&path)?.psk,
        (None, None) => BridgeConfig::load(&BridgeConfig::default_config_path())?.psk,
    };

    let bind_addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&bind_addr)?;
    println!("[test-live] Listening on {bind_addr} — waiting for Android Pixel SSH Agent...");

    let (mut stream, peer) = listener.accept()?;
    println!("[test-live] Accepted TCP connection from {peer}");
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(65)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let (send_key, recv_key) = handshake_server(&mut stream, &psk)?;
    println!("[test-live] PASS: PSA1 mutual authentication & X25519/HKDF handshake succeeded!");

    let write_stream = stream.try_clone()?;
    let mut writer = Psa1Writer::new(write_stream, &send_key);
    let mut reader = Psa1Reader::new(stream, &recv_key);

    // 1. Ping -> Pong
    writer.write_record(&TunnelFrame::Ping.encode())?;
    let pong = TunnelFrame::decode(&reader.read_record()?)?;
    if pong != TunnelFrame::Pong {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Expected Pong, got {pong:?}"),
        ));
    }
    println!("[test-live] PASS: Encrypted Ping/Pong keepalive verified!");

    // 2. Open channel #1 & REQUEST_IDENTITIES (11)
    writer.write_record(&TunnelFrame::Open { channel_id: 1 }.encode())?;
    writer.write_record(
        &TunnelFrame::Data {
            channel_id: 1,
            payload: vec![11],
        }
        .encode(),
    )?;

    let resp_frame = TunnelFrame::decode(&reader.read_record()?)?;
    let payload = match resp_frame {
        TunnelFrame::Data {
            channel_id: 1,
            payload,
        } => payload,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Expected Data on channel 1, got {other:?}"),
            ))
        }
    };

    if payload.first().copied() != Some(12) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected SSH_AGENT_IDENTITIES_ANSWER (12), got {:?}",
                payload.first()
            ),
        ));
    }

    let mut pos = 1usize;
    let nkeys = read_u32_be(&payload, &mut pos)?;
    println!("[test-live] PASS: REQUEST_IDENTITIES returned {nkeys} key(s):");

    let mut keys: Vec<(Vec<u8>, String)> = Vec::new();
    for idx in 0..nkeys {
        let blob = read_ssh_bytes(&payload, &mut pos)?;
        let comment_bytes = read_ssh_bytes(&payload, &mut pos)?;
        let comment = String::from_utf8_lossy(&comment_bytes).into_owned();
        let mut bpos = 0usize;
        let algo = String::from_utf8_lossy(&read_ssh_bytes(&blob, &mut bpos)?).into_owned();
        let fp_hex = hex::encode(Sha256::digest(&blob));
        println!("  [{idx}] algo={algo} comment=\"{comment}\" sha256_hex={fp_hex}");
        keys.push((blob, comment));
    }

    // 3. Test SIGN_REQUEST (13) on each returned key
    for (idx, (blob, comment)) in keys.iter().enumerate() {
        let challenge = b"pixel-ssh-agent-live-emulator-challenge";
        let mut req = Vec::new();
        req.push(13u8);
        write_ssh_bytes(&mut req, blob);
        write_ssh_bytes(&mut req, challenge);
        req.extend_from_slice(&0u32.to_be_bytes()); // flags = 0

        println!("[test-live] Sending SIGN_REQUEST for key [{idx}] \"{comment}\"...");
        writer.write_record(
            &TunnelFrame::Data {
                channel_id: 1,
                payload: req,
            }
            .encode(),
        )?;

        let sign_frame = TunnelFrame::decode(&reader.read_record()?)?;
        let sign_payload = match sign_frame {
            TunnelFrame::Data {
                channel_id: 1,
                payload,
            } => payload,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Expected Data on channel 1, got {other:?}"),
                ))
            }
        };

        match sign_payload.first().copied() {
            Some(14) => {
                let mut spos = 1usize;
                let sig_blob = read_ssh_bytes(&sign_payload, &mut spos)?;
                let mut sbpos = 0usize;
                let sig_algo =
                    String::from_utf8_lossy(&read_ssh_bytes(&sig_blob, &mut sbpos)?).into_owned();
                let sig_raw = read_ssh_bytes(&sig_blob, &mut sbpos)?;
                println!(
                    "[test-live] PASS: SIGN_RESPONSE received! algo={sig_algo}, sig_bytes={}",
                    sig_raw.len()
                );
            }
            Some(5) => {
                println!(
                    "[test-live] INFO: Received SSH_AGENT_FAILURE (5) — user denied or timed out."
                );
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unexpected SIGN_REQUEST response code: {other:?}"),
                ));
            }
        }
    }

    writer.write_record(&TunnelFrame::Close { channel_id: 1 }.encode())?;
    println!("[test-live] ALL LIVE CHECKS COMPLETE.");
    Ok(())
}

fn read_u32_be(buf: &[u8], pos: &mut usize) -> std::io::Result<u32> {
    if *pos + 4 > buf.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Unexpected EOF reading uint32",
        ));
    }
    let val = u32::from_be_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
    *pos += 4;
    Ok(val)
}

fn read_ssh_bytes(buf: &[u8], pos: &mut usize) -> std::io::Result<Vec<u8>> {
    let len = read_u32_be(buf, pos)? as usize;
    if *pos + len > buf.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Unexpected EOF reading ssh string",
        ));
    }
    let slice = buf[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(slice)
}

fn write_ssh_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
