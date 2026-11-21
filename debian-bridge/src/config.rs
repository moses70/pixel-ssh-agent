use rand::{rngs::OsRng, RngCore};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub bind_addr: String,
    pub socket_path: PathBuf,
    pub psk: [u8; 32],
}

impl BridgeConfig {
    pub fn default_config_path() -> PathBuf {
        if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return PathBuf::from(xdg)
                    .join("pixel-ssh-agent")
                    .join("config.env");
            }
        }
        let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join(".config")
            .join("pixel-ssh-agent")
            .join("config.env")
    }

    pub fn default_socket_path() -> PathBuf {
        if let Ok(runtime) = env::var("XDG_RUNTIME_DIR") {
            if !runtime.is_empty() {
                return PathBuf::from(runtime).join("pixel-ssh-agent.sock");
            }
        }
        let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".ssh").join("pixel-ssh-agent.sock")
    }

    pub fn generate_random_psk() -> [u8; 32] {
        let mut psk = [0u8; 32];
        OsRng.fill_bytes(&mut psk);
        psk
    }

    pub fn parse_psk_hex(raw: &str) -> io::Result<[u8; 32]> {
        let cleaned: String = raw
            .chars()
            .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
            .collect();
        let bytes = hex::decode(&cleaned)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid PSK hex: {e}")))?;
        bytes.try_into().map_err(|v: Vec<u8>| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("PSK must be 32 bytes (64 hex chars), got {} bytes", v.len()),
            )
        })
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = format!(
            "# Pixel SSH Agent Bridge configuration\n\
             BIND_ADDR={}\n\
             SOCKET_PATH={}\n\
             PSK_HEX={}\n",
            self.bind_addr,
            self.socket_path.display(),
            hex::encode(self.psk)
        );
        fs::write(path, content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let raw = fs::read_to_string(path)?;
        let mut bind_addr = "0.0.0.0:22999".to_string();
        let mut socket_path = Self::default_socket_path();
        let mut psk: Option<[u8; 32]> = None;

        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = trimmed.split_once('=') {
                match key.trim() {
                    "BIND_ADDR" => bind_addr = value.trim().to_string(),
                    "SOCKET_PATH" => socket_path = PathBuf::from(value.trim()),
                    "PSK_HEX" => psk = Some(Self::parse_psk_hex(value.trim())?),
                    _ => {}
                }
            }
        }

        let psk = psk.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing PSK_HEX in config file; run `pixel-ssh-agent-bridge init`",
            )
        })?;

        Ok(Self {
            bind_addr,
            socket_path,
            psk,
        })
    }
}
