# Project Summary: Pixel SSH Agent

This document summarizes the architecture decisions, implemented components, and verification results for **Pixel SSH Agent**—a from-scratch Android SSH agent tailored to the built-in **Pixel Linux Terminal (Debian VM via AVF)**.

---

## 1. Goal & Key Architectural Decisions

The goal is to keep private SSH keys permanently protected on the Android host (inside **Android Keystore / StrongBox** with optional **BiometricPrompt** confirmation) so they never exist as files inside the Debian VM, while letting OpenSSH in Debian use them transparently via `SSH_AUTH_SOCK`.

1. **Transport Direction — Reverse TCP over AVF Port Forwarding:**
   - The Rust bridge inside Debian listens on TCP port `22999`.
   - The Pixel Linux Terminal's built-in AVF port forwarding maps this port strictly onto `127.0.0.1:22999` on the Android host (no ports exposed on external networks).
   - The Android app connects as a TCP client from a `ForegroundService` and keeps the encrypted tunnel alive with exponential backoff reconnects and keepalive pings.
2. **Rust Debian Bridge (Zero C Dependencies):**
   - Uses pure Rust (`std::net`, `std::os::unix::net`, `std::thread`) plus `RustCrypto` crates (`x25519-dalek`, `aes-gcm`, `hkdf`, `hmac`, `sha2`, `subtle`).
   - Builds fast directly inside Debian ARM64 without `libssl-dev` or async runtime overhead.
3. **MVP Scope:**
   - OpenSSH Agent Protocol from scratch (`REQUEST_IDENTITIES`, `SIGN_REQUEST`, `EXTENSION` → `EXTENSION_FAILURE`).
   - Key types: **ECDSA P-256** (Android Keystore / StrongBox) and **Ed25519** (pure-Kotlin RFC 8032, 32-byte seed wrapped with Android Keystore AES-256-GCM).
   - Mutually authenticated & encrypted `PSA1` tunnel + configurable biometric approval.

---

## 2. Implemented Components

### Documentation & Repository Hygiene
- [`README.md`](../README.md) — Overview, quick start, `systemd --user` setup, and emulator live test instructions.
- [`docs/PROTOCOL.md`](PROTOCOL.md) — Byte-level specification of all 4 protocol layers.
- [`docs/TECHNICAL_BACKGROUND.md`](TECHNICAL_BACKGROUND.md) — Deep-dive educational guide.
- [`SECURITY.md`](../SECURITY.md) — Threat model, side-channel caveats, and vulnerability disclosure policy.
- [`LICENSE`](../LICENSE) — MIT License.
- [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — GitHub Actions CI for Rust (`fmt`, `clippy`, `test`, `build --release`) and Android (`testDebugUnitTest`, `assembleDebug`).

### Android App (`android-app/`, `io.github.moses70.pixelsshagent`)
- **SSH Protocol Layer (`ssh/`):**
  - `SshWire.kt` — RFC 4251 binary codec (`byte`, `uint32`, `string`, `mpint`).
  - `SshPublicKey.kt` — OpenSSH public key blobs (`ecdsa-sha2-nistp256`, `ssh-ed25519`), `authorized_keys` export, and `SHA256:` fingerprints.
  - `SshSignature.kt` — ASN.1 DER → OpenSSH ECDSA signature conversion and Ed25519 signature formatting.
  - `SshAgentProtocol.kt` — `draft-miller-ssh-agent` parser and suspending dispatcher.
- **Cryptography & Key Storage (`crypto/`):**
  - `X25519Pure.kt` — Pure-Kotlin RFC 7748 X25519 Montgomery ladder.
  - `Ed25519Pure.kt` — Pure-Kotlin RFC 8032 Ed25519 signing and verification.
  - `TunnelCrypto.kt` — RFC 5869 HKDF-SHA256, `PSA1` client/server handshake, and AES-256-GCM record session.
  - `KeyRepository.kt` — Manages StrongBox/TEE ECDSA P-256 keys and Keystore-wrapped Ed25519 seeds.
- **Tunnel, Service & UI (`tunnel/`, `service/`, `ui/`):**
  - `TunnelFrame.kt` & `TunnelClient.kt` — Multiplexed frame codec and resilient TCP client.
  - `SettingsStore.kt`, `AgentCoordinator.kt`, `AgentForegroundService.kt` — Pairing config, activity log, biometric approval queue & unlock window, and `specialUse` ForegroundService.
  - `MainActivity.kt` — Material 3 Jetpack Compose UI (**Tunnel**, **Keys**, **Log** tabs) + `BiometricPrompt` integration + adaptive vector app icon.

### Rust Debian Bridge (`debian-bridge/`)
- `src/crypto.rs` — Server-side `PSA1` handshake, AES-256-GCM record framing, and cross-language test vector.
- `src/tunnel.rs` — Multiplexed `TunnelFrame` codec, `BridgeHub`, and `ActiveTunnel` session management.
- `src/unix_agent.rs` — `0600` Unix domain socket (`SSH_AUTH_SOCK`) listener with RAII `ChannelGuard`.
- `src/config.rs` & `src/main.rs` — CLI (`init`, `run`, `print-env`, and cross-platform `test-live`).
- `systemd/pixel-ssh-agent-bridge.service` — Ready-to-use `systemd --user` service unit.

---

## 3. Verification & Test Results

### Android JVM Unit Tests & Build
- `./gradlew testDebugUnitTest assembleDebug` — Warning-free build, all tests passing:
  - RFC 4251 `mpint` & OpenSSH ECDSA/Ed25519 wire format round-trips
  - RFC 7748 Section 6.1 X25519 test vector
  - RFC 8032 Section 7.1 Ed25519 test vectors (TEST 1, 2, 3)
  - RFC 5869 HKDF-SHA256 Test Case 1
  - PSK mismatch rejection
  - Deterministic cross-language `PSA1` key derivation vector
  - End-to-end TCP loopback tunnel with Ed25519 signing

### Rust Unit Tests & Linting
- `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` — Zero warnings, all tests passing, including `psa1_cross_language_key_derivation_matches_kotlin` matching Kotlin byte-for-byte.

### Live Emulator Integration Test (`emulator-5554`)
- Installed Debug APK on `emulator-5554`, forwarded port `22999` via `adb reverse tcp:22999 tcp:22999`, generated an AndroidKeyStore `ecdsa-sha2-nistp256` key (`pixel@emu`), copied the pairing command from the app UI, and ran `pixel-ssh-agent-bridge test-live`:
  - `PSA1` mutual authentication & X25519/HKDF handshake: **PASS**
  - Encrypted Ping/Pong keepalive: **PASS**
  - `REQUEST_IDENTITIES`: **PASS** (`ecdsa-sha2-nistp256`, `pixel@emu`)
  - Interactive `SIGN_REQUEST` → `SIGN_RESPONSE` (73 bytes): **PASS**

---

## 4. Roadmap Ideas (Post-MVP)
- Cryptographic signature verification inside `test-live` against returned public keys (ECDSA P-256 & Ed25519).
- Prefer native Android 13+ (API 33+) JCA `X25519` and `Ed25519` providers where available, keeping pure-Kotlin fallback for older APIs.
- Support OpenSSH `session-bind@openssh.com` extension to display target host information in biometric prompts.
- Additional agent commands (`SSH_AGENTC_LOCK` / `UNLOCK`, RSA-SHA2, QR-code pairing).
- End-to-end verification inside a physical Pixel AVF Debian VM.
