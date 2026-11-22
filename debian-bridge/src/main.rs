mod config;
mod crypto;
mod tunnel;
mod unix_agent;

use config::BridgeConfig;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tunnel::BridgeHub;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellFormat {
    Bourne,
    Csh,
}

fn print_usage() {
    eprintln!(
        "pixel-ssh-agent-bridge — Encrypted SSH-Agent Bridge for Pixel Linux Terminal (AVF)\n\n\
         SSH-AGENT COMPATIBLE USAGE (starts daemon in background & prints shell env):\n\
           eval \"$(pixel-ssh-agent-bridge)\"\n\
           eval \"$(pixel-ssh-agent-bridge -s [-a <SOCKET>] [--port <PORT>] [--psk <64-HEX>])\"\n\
           eval \"$(pixel-ssh-agent-bridge -k)\"          # stop running bridge daemon\n\
           pixel-ssh-agent-bridge -D                    # run in foreground (like ssh-agent -D)\n\n\
         EXPLICIT SUBCOMMANDS:\n\
           pixel-ssh-agent-bridge init      [--port <PORT>] [--psk <64-HEX>] [--socket <PATH>] [--config <PATH>]\n\
           pixel-ssh-agent-bridge run       [--config <PATH>] [--bind <ADDR:PORT>] [--socket <PATH>]\n\
           pixel-ssh-agent-bridge stop      [--config <PATH>]\n\
           pixel-ssh-agent-bridge print-env [--config <PATH>]\n\
           pixel-ssh-agent-bridge test-live [--port <PORT>] [--psk <64-HEX>] [--config <PATH>]\n"
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    let res = match args.first().map(String::as_str) {
        None => cmd_ssh_agent_mode(&[]),
        Some("init") => cmd_init(&args[1..]),
        Some("run") => cmd_run(&args[1..]),
        Some("stop") => cmd_kill(&args[1..], ShellFormat::Bourne),
        Some("print-env") => cmd_print_env(&args[1..]),
        Some("test-live") => cmd_test_live(&args[1..]),
        Some("-h" | "--help" | "help") => {
            print_usage();
            Ok(())
        }
        Some(first) if first.starts_with('-') => cmd_ssh_agent_mode(&args),
        Some(other) => {
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

/// Behaves like OpenSSH `ssh-agent`:
/// - Ensures the bridge daemon is running in the background (idempotent if already active)
/// - Prints `SSH_AUTH_SOCK=...; export SSH_AUTH_SOCK; SSH_AGENT_PID=...; export SSH_AGENT_PID;`
/// - Supports `-s` (Bourne shell), `-c` (C-shell), `-k` (kill), `-D`/`-d` (foreground), `-a <sock>`,
///   plus optional `--port` and `--psk` to initialize config on the fly.
fn cmd_ssh_agent_mode(args: &[String]) -> io::Result<()> {
    let mut shell = ShellFormat::Bourne;
    let mut kill_mode = false;
    let mut foreground_mode = false;
    let mut config_path = BridgeConfig::default_config_path();
    let mut socket_override: Option<PathBuf> = None;
    let mut port_override: Option<u16> = None;
    let mut psk_override: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-s" => shell = ShellFormat::Bourne,
            "-c" => shell = ShellFormat::Csh,
            "-k" => kill_mode = true,
            "-D" | "-d" => foreground_mode = true,
            "-a" | "--socket" => {
                i += 1;
                let raw = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "-a/--socket requires a path")
                })?;
                socket_override = Some(PathBuf::from(raw));
            }
            "--port" => {
                i += 1;
                let raw = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--port requires a value")
                })?;
                port_override = Some(raw.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "Invalid port number")
                })?);
            }
            "--psk" => {
                i += 1;
                psk_override = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "--psk requires a value")
                        })?
                        .clone(),
                );
            }
            "--config" => {
                i += 1;
                let raw = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--config requires a value")
                })?;
                config_path = PathBuf::from(raw);
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

    if kill_mode {
        return cmd_kill_with_config(&config_path, socket_override.as_deref(), shell);
    }

    // If --psk was supplied, initialize or update the config file automatically.
    if let Some(ref psk_hex) = psk_override {
        let psk = BridgeConfig::parse_psk_hex(psk_hex)?;
        let existing = BridgeConfig::load(&config_path).ok();
        let bind_addr = match port_override {
            Some(p) => format!("0.0.0.0:{p}"),
            None => existing
                .as_ref()
                .map(|c| c.bind_addr.clone())
                .unwrap_or_else(|| "0.0.0.0:22999".to_string()),
        };
        let socket_path = socket_override
            .clone()
            .or_else(|| existing.map(|c| c.socket_path))
            .unwrap_or_else(BridgeConfig::default_socket_path);
        let new_cfg = BridgeConfig {
            bind_addr,
            socket_path,
            psk,
        };
        new_cfg.save(&config_path)?;
    }

    let mut cfg = BridgeConfig::load(&config_path)?;
    if let Some(port) = port_override {
        cfg.bind_addr = format!("0.0.0.0:{port}");
    }
    if let Some(sock) = socket_override {
        cfg.socket_path = sock;
    }

    if foreground_mode {
        return run_foreground_server(cfg);
    }

    // Check if an instance is already listening on the Unix socket (idempotent behavior for .bashrc).
    let pid_path = pid_file_path(&cfg.socket_path);
    if is_socket_alive(&cfg.socket_path) {
        let existing_pid = read_pid_file(&pid_path).unwrap_or_else(process::id);
        print_agent_env(&cfg.socket_path, existing_pid, shell);
        return Ok(());
    }

    // Spawn detached background daemon with stdio redirected to /dev/null so `$(...)` never hangs.
    let exe = env::current_exe()?;
    let mut child = Command::new(exe)
        .arg("run")
        .arg("--config")
        .arg(&config_path)
        .arg("--bind")
        .arg(&cfg.bind_addr)
        .arg("--socket")
        .arg(&cfg.socket_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let pid = child.id();
    let _ = write_pid_file(&pid_path, pid);

    // Wait briefly (up to 600ms) for the Unix socket to become ready or report early startup errors.
    for _ in 0..30 {
        if is_socket_alive(&cfg.socket_path) {
            break;
        }
        if let Some(status) = child.try_wait()? {
            let _ = fs::remove_file(&pid_path);
            return Err(io::Error::other(format!(
                "Bridge daemon exited early with {status} (check if port in {} is already in use)",
                cfg.bind_addr
            )));
        }
        thread::sleep(Duration::from_millis(20));
    }

    print_agent_env(&cfg.socket_path, pid, shell);
    Ok(())
}

fn print_agent_env(socket_path: &Path, pid: u32, shell: ShellFormat) {
    let sock = socket_path.display();
    match shell {
        ShellFormat::Bourne => {
            println!("SSH_AUTH_SOCK={sock}; export SSH_AUTH_SOCK;");
            println!("SSH_AGENT_PID={pid}; export SSH_AGENT_PID;");
            println!("echo Agent pid {pid};");
        }
        ShellFormat::Csh => {
            println!("setenv SSH_AUTH_SOCK {sock};");
            println!("setenv SSH_AGENT_PID {pid};");
            println!("echo Agent pid {pid};");
        }
    }
}

fn pid_file_path(socket_path: &Path) -> PathBuf {
    let mut os = socket_path.as_os_str().to_os_string();
    os.push(".pid");
    PathBuf::from(os)
}

fn write_pid_file(pid_path: &Path, pid: u32) -> io::Result<()> {
    if let Some(parent) = pid_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(pid_path, format!("{pid}\n"))
}

fn read_pid_file(pid_path: &Path) -> Option<u32> {
    fs::read_to_string(pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

fn is_socket_alive(socket_path: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(socket_path).is_ok()
    }
    #[cfg(not(unix))]
    {
        socket_path.exists()
    }
}

fn cmd_kill(args: &[String], shell: ShellFormat) -> io::Result<()> {
    let config_path = parse_config_path(args)?;
    cmd_kill_with_config(&config_path, None, shell)
}

fn cmd_kill_with_config(
    config_path: &Path,
    socket_override: Option<&Path>,
    shell: ShellFormat,
) -> io::Result<()> {
    let socket_path = match socket_override {
        Some(p) => p.to_path_buf(),
        None => BridgeConfig::load(config_path)
            .map(|c| c.socket_path)
            .unwrap_or_else(|_| BridgeConfig::default_socket_path()),
    };
    let pid_path = pid_file_path(&socket_path);

    let pid = env::var("SSH_AGENT_PID")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .or_else(|| read_pid_file(&pid_path))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "SSH_AGENT_PID not set and no PID file found",
            )
        })?;

    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .arg(pid.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_file(&pid_path);

    match shell {
        ShellFormat::Bourne => {
            println!("unset SSH_AUTH_SOCK;");
            println!("unset SSH_AGENT_PID;");
            println!("echo Agent pid {pid} killed;");
        }
        ShellFormat::Csh => {
            println!("unsetenv SSH_AUTH_SOCK;");
            println!("unsetenv SSH_AGENT_PID;");
            println!("echo Agent pid {pid} killed;");
        }
    }
    Ok(())
}

fn cmd_init(args: &[String]) -> io::Result<()> {
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
                    io::Error::new(io::ErrorKind::InvalidInput, "--port requires a value")
                })?;
                port = raw.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "Invalid port number")
                })?;
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
            "--socket" => {
                i += 1;
                let raw = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--socket requires a value")
                })?;
                socket_path = PathBuf::from(raw);
            }
            "--config" => {
                i += 1;
                let raw = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--config requires a value")
                })?;
                config_path = PathBuf::from(raw);
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
    println!("  1. Start & export (like ssh-agent):  eval \"$(pixel-ssh-agent-bridge)\"");
    println!("  2. Enable port forwarding for port {port} in Pixel Linux Terminal settings.");
    Ok(())
}

fn cmd_print_env(args: &[String]) -> io::Result<()> {
    let config_path = parse_config_path(args)?;
    let cfg = BridgeConfig::load(&config_path)?;
    let pid = read_pid_file(&pid_file_path(&cfg.socket_path)).unwrap_or(0);
    if pid > 0 {
        print_agent_env(&cfg.socket_path, pid, ShellFormat::Bourne);
    } else {
        println!(
            "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;",
            cfg.socket_path.display()
        );
    }
    Ok(())
}

fn cmd_run(args: &[String]) -> io::Result<()> {
    let mut config_path = BridgeConfig::default_config_path();
    let mut bind_override: Option<String> = None;
    let mut socket_override: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                config_path = PathBuf::from(args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--config requires a value")
                })?);
            }
            "--bind" => {
                i += 1;
                bind_override = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "--bind requires a value")
                        })?
                        .clone(),
                );
            }
            "--socket" => {
                i += 1;
                socket_override = Some(PathBuf::from(args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--socket requires a value")
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

    let mut cfg = BridgeConfig::load(&config_path)?;
    if let Some(bind) = bind_override {
        cfg.bind_addr = bind;
    }
    if let Some(sock) = socket_override {
        cfg.socket_path = sock;
    }

    run_foreground_server(cfg)
}

fn run_foreground_server(cfg: BridgeConfig) -> io::Result<()> {
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
        let _ = cfg.socket_path;
        let _ = hub;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unix domain SSH_AUTH_SOCK server requires Linux/Unix (run inside Pixel Debian VM)",
        ))
    }
}

fn parse_config_path(args: &[String]) -> io::Result<PathBuf> {
    let mut config_path = BridgeConfig::default_config_path();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--config" {
            i += 1;
            let raw = args.get(i).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "--config requires a value")
            })?;
            config_path = PathBuf::from(raw);
        }
        i += 1;
    }
    Ok(config_path)
}

/// Cross-platform live integration test against a running Android app (emulator or device).
/// Listens on TCP, performs the PSA1 handshake, tests Ping/Pong, REQUEST_IDENTITIES, and SIGN_REQUEST.
fn cmd_test_live(args: &[String]) -> io::Result<()> {
    use crate::crypto::{handshake_server, Psa1Reader, Psa1Writer};
    use crate::tunnel::TunnelFrame;
    use sha2::{Digest, Sha256};
    use std::net::TcpListener;

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

fn read_u32_be(buf: &[u8], pos: &mut usize) -> io::Result<u32> {
    if *pos + 4 > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Unexpected EOF reading uint32",
        ));
    }
    let val = u32::from_be_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
    *pos += 4;
    Ok(val)
}

fn read_ssh_bytes(buf: &[u8], pos: &mut usize) -> io::Result<Vec<u8>> {
    let len = read_u32_be(buf, pos)? as usize;
    if *pos + len > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
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
