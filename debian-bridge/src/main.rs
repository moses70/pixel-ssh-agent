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
           pixel-ssh-agent-bridge init [--port <PORT>] [--psk <64-HEX>] [--socket <PATH>] [--config <PATH>]\n\
           pixel-ssh-agent-bridge run  [--config <PATH>] [--bind <ADDR:PORT>] [--socket <PATH>]\n\
           pixel-ssh-agent-bridge print-env [--config <PATH>]\n"
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
