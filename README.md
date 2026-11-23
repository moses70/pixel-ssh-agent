# Pixel SSH Agent

[![CI](https://github.com/moses70/pixel-ssh-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/moses70/pixel-ssh-agent/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A **from-scratch SSH agent for Android** designed specifically for the built-in **Pixel Linux Terminal (Debian VM via Android Virtualization Framework / AVF)**.

Private SSH keys never enter the Debian VM. They remain on the Android host—backed by **Android Keystore / StrongBox** (ECDSA P-256) or Keystore-AES-GCM envelope encryption (Ed25519)—and can require interactive **BiometricPrompt** confirmation per signature. A lightweight, zero-C-dependency **Rust bridge** inside Debian exposes a standard `SSH_AUTH_SOCK` Unix socket to `ssh`, `git`, `scp`, and `ssh-add`.

<p align="center">
  <img src="docs/images/tunnel-connected.jpg" alt="Pixel SSH Agent connected to Debian VM with active biometric unlock countdown" width="320" />
</p>

---

## Architecture (Reverse TCP over AVF Port Forwarding)

```text
[Pixel Debian VM (AVF)]                                [Android Host]
ssh / git / ssh-add -L
   │  (OpenSSH Agent Protocol over Unix socket)
   ▼
pixel-ssh-agent-bridge (Rust)
   │  Listens on TCP 0.0.0.0:22999
   │  ◄──── AVF Port Forwarding (127.0.0.1:22999) ────►
   │                                                   Pixel SSH Agent (Kotlin)
   │                                                   • Connects as TCP client
   │                                                   • PSA1 handshake (X25519 + PSK)
   │                                                   • AES-256-GCM record framing
   │                                                   • OpenSSH Agent dispatcher
   │                                                   • Keystore / StrongBox + Biometrics
```

Why reverse TCP over AVF port forwarding?
- The Pixel Linux Terminal maps forwarded guest ports **strictly to `127.0.0.1`** on Android (nothing exposed on Wi-Fi or mobile networks).
- Because all Android apps with `INTERNET` permission share `127.0.0.1`, the custom **`PSA1`** protocol enforces **mutual authentication + forward-secret end-to-end encryption** using a one-time paired 256-bit Pre-Shared Key (PSK) and ephemeral X25519.

---

## Features (MVP)

- **OpenSSH Agent Protocol from scratch** (`draft-miller-ssh-agent`: `REQUEST_IDENTITIES`, `SIGN_REQUEST`, RFC 4251 wire codec, SHA-256 fingerprints, `authorized_keys` export)
- **Key algorithms & import:**
  - `ecdsa-sha2-nistp256` — Hardware-backed via Android Keystore / StrongBox (DER → OpenSSH wire conversion)
  - `ssh-ed25519` — Pure-Kotlin RFC 8032 implementation with 32-byte private seeds wrapped by an Android Keystore AES-256-GCM master key
  - **OpenSSH private key import** — Load from file or paste `-----BEGIN OPENSSH PRIVATE KEY-----` (plain or `bcrypt_pbkdf` passphrase-encrypted `aes256-ctr` / `aes256-gcm@openssh.com`), encrypted at rest with the Android Keystore master key
- **Authenticated & encrypted tunnel (`PSA1`):**
  - Ephemeral X25519 (RFC 7748) + 256-bit PSK + HKDF-SHA256 (RFC 5869) + directional AES-256-GCM with implicit sequence nonces and AAD
  - Multiplexed channels (`OPEN` / `DATA` / `CLOSE` / `PING` / `PONG`) for concurrent SSH sessions
- **Biometric confirmation:** Interactive approval via Android `BiometricPrompt` with optional unlock window (`Every sign` / `1 min` / `5 min` / `15 min` / `30 min`), live countdown, and instant **Lock Now** button
- **Cross-language test parity:** Deterministic `PSA1` key-derivation test vectors verified identically in both Kotlin and Rust unit tests

---

## Repository Layout

| Path | Description |
|------|-------------|
| [`android-app/`](android-app/) | Native Android app (`io.github.moses70.pixelsshagent`) in Kotlin + Jetpack Compose (Material 3) |
| [`debian-bridge/`](debian-bridge/) | Pure-Rust daemon (`pixel-ssh-agent-bridge`) + `systemd --user` service unit |
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | Complete byte-level specification of `PSA1` and the SSH agent layers |
| [`docs/TECHNICAL_BACKGROUND.md`](docs/TECHNICAL_BACKGROUND.md) | Deep-dive technical guide covering SSH wire format, Keystore, AVF, and `PSA1` crypto |
| [`docs/SUMMARY.md`](docs/SUMMARY.md) | Project milestones, architecture decisions, and verification results |
| [`SECURITY.md`](SECURITY.md) | Threat model, cryptographic caveats, and vulnerability reporting |

---

## Quick Start

### 1. Build & Install the Android App

```bash
cd android-app
./gradlew testDebugUnitTest assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### 2. Build the Rust Bridge in Pixel Linux Terminal (Debian)

Copy `debian-bridge/` into your Debian VM (e.g. via `/mnt/shared`) and build:

```bash
# Install Rust if not present:
sudo apt update && sudo apt install -y cargo rustc

cd ~/debian-bridge
cargo test
cargo build --release

mkdir -p ~/.local/bin
cp target/release/pixel-ssh-agent-bridge ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"
```

### 3. Pair & Enable AVF Port Forwarding

1. Open **Pixel SSH Agent** on your Pixel:
   - Go to the **Keys** tab and tap **+** to generate an `ECDSA P-256 (HW)` or `Ed25519` key.
   - Switch to the **Tunnel** tab and tap **Copy Debian Init**.
2. Paste and run the one-time init command inside the **Pixel Linux Terminal**:
   ```bash
   pixel-ssh-agent-bridge init --port 22999 --psk <64-hex-chars>
   ```
3. Start the bridge and export environment variables in one step—**just like `ssh-agent`**:
   ```bash
   eval "$(pixel-ssh-agent-bridge)"
   ```
   *(Or do step 2 + 3 in a single command: `eval "$(pixel-ssh-agent-bridge --port 22999 --psk <64-hex-chars>)"`)*
4. **Allow port `22999`** when prompted by the Pixel Linux Terminal (or configure it under *Terminal Settings → Port control*).
5. Tap **Start Agent** in the Android app → status switches to **Connected to Debian VM**.

### 4. Use with OpenSSH (`ssh-agent` Compatible CLI)

`pixel-ssh-agent-bridge` supports standard `ssh-agent` flags (`-s`, `-c`, `-k`, `-D`, `-a <socket>`) and is **idempotent**—if the daemon is already running, `eval "$(pixel-ssh-agent-bridge)"` simply outputs the existing `SSH_AUTH_SOCK` and `SSH_AGENT_PID` without spawning a duplicate process:

```bash
# Start background daemon (if not running) and export SSH_AUTH_SOCK & SSH_AGENT_PID:
eval "$(pixel-ssh-agent-bridge)"

# List public keys held on Android:
ssh-add -L

# Authenticate to a remote server (triggers biometric prompt if enabled):
ssh user@your-server

# Stop the running background daemon (like ssh-agent -k):
eval "$(pixel-ssh-agent-bridge -k)"
```

Copy the corresponding `authorized_keys` line directly from the **Keys** tab in the Android app.

### 5. Optional: Auto-start in `~/.bashrc` or via `systemd --user`

Because `eval "$(pixel-ssh-agent-bridge)"` is idempotent, you can simply add one line to `~/.bashrc`:

```bash
if command -v pixel-ssh-agent-bridge >/dev/null 2>&1; then
    eval "$(pixel-ssh-agent-bridge)" >/dev/null
fi
```

Alternatively, if you prefer a `systemd --user` service (`pixel-ssh-agent-bridge -D` / `run`):

```bash
mkdir -p ~/.config/systemd/user
cp ~/debian-bridge/systemd/pixel-ssh-agent-bridge.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now pixel-ssh-agent-bridge.service
```

To export `SSH_AUTH_SOCK` in your shell when running via `systemd --user`, add either `eval "$(pixel-ssh-agent-bridge print-env)"` or `eval "$(pixel-ssh-agent-bridge)" >/dev/null` to `~/.bashrc` (the CLI detects an active or starting `systemd --user` service and waits for its socket rather than starting a duplicate daemon).

### 6. Optional: Agent "borrow" for a next level of agent forwarding

Agent forwarding is very nice when the agent lives on you main workstation. But with pixel-ssh-agent,
a little bit more freedom would be nice.
You can add this snippet to the .bashrc of your main workstation: With it, the SSH_AUTH_SOCK will be cached in a file '~/.pixel_auth'
and every new session will have the socket as well.
A 'key' symbol 🔑 is added to the prompt to make this always visible.

```bash
# Borrow ssh-agent
alias psa-exists='ssh-add -l 2>/dev/null | grep DroidKey >/dev/null'
if (psa-exists)
then
        echo "export SSH_AUTH_SOCK=$SSH_AUTH_SOCK" > ~/.pixel_auth
        chmod 600 ~/.pixel_auth
        PIXEL_AUTH=1
elif [ -f ~/.pixel_auth ]
then
        . ~/.pixel_auth
        if (psa-exists)
        then
               PIXEL_AUTH=1
        else
               rm ~/.pixel_auth
        fi
fi

if [ -n "$PIXEL_AUTH" ]
then
        PS1="🔑 $PS1"
fi
```

And this addition to .ssh/config allows to activate the bridge with only one command:
```
# Goes to the pixel and back, activating agent forwarding (with borrow, see above):
Host pb
    Hostname pixel.the-tail-net-name.ts.net
    User droid
    HostKeyAlias MyPixel
    RequestTTY yes
    ForwardAgent no
    RemoteCommand bash -lc 'eval "$(pixel-ssh-agent-bridge)" >/dev/null && exec ssh zen'
```

---

## Live Testing Against an Android Emulator (Without a Pixel VM)

You can test the full encrypted Rust ↔ Android pipeline on your desktop using the built-in `test-live` subcommand:

```bash
adb reverse tcp:22999 tcp:22999
cd debian-bridge
cargo run -- test-live --port 22999 --psk <64-hex-psk-from-app>
```

Then tap **Start Agent** in the emulator app to verify `PSA1` handshake, Ping/Pong keepalive, `REQUEST_IDENTITIES`, and interactive `SIGN_REQUEST`.

---

## Security Notice

Please read [`SECURITY.md`](SECURITY.md) before using this project for sensitive production keys. In particular, this is an early MVP (`0.1.0`) and the pure-Kotlin `BigInteger` Ed25519/X25519 implementations are not constant-time; hardware-backed **ECDSA P-256** is recommended for maximum key isolation.

## License

Licensed under the [MIT License](LICENSE).
