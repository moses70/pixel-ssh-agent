# Security Policy

## Scope & Threat Model

**Pixel SSH Agent** is designed to keep private SSH keys on the Android host (backed by Android Keystore / StrongBox and optional biometric confirmation) while exposing SSH signing capabilities to the Pixel Linux Terminal (Android Virtualization Framework / Debian VM) via a local Unix socket (`SSH_AUTH_SOCK`).

### What `PSA1` Protects Against
- **Unprivileged Android apps connecting to `127.0.0.1:<port>`:** Because AVF port forwarding exposes guest ports on Android's shared loopback interface, `PSA1` enforces mutual authentication via a 256-bit Pre-Shared Key (PSK) bound to an ephemeral X25519 key exchange and full handshake transcript (`HKDF-SHA256` + constant-time `HMAC-SHA256`).
- **Passive observation, tampering, replay, and reordering:** All post-handshake traffic is encrypted with directional `AES-256-GCM` keys, strictly monotonic implicit sequence nonces, and AAD binding both record length and sequence number.
- **Silent unauthorized SSH logins:** Keys can require interactive approval via Android `BiometricPrompt` (per signature or with a configurable unlock window).

### Known Limitations & Cryptographic Caveats
1. **Pure-Kotlin Curve Arithmetic (`BigInteger`) Is Not Constant-Time:**
   - `X25519Pure.kt` and `Ed25519Pure.kt` are clean-room, RFC-verified pure-Kotlin implementations built on `java.math.BigInteger` for broad Android API 28+ compatibility without native dependencies.
   - `BigInteger` operations are **not constant-time** and may exhibit timing side channels against a co-located attacker capable of fine-grained local timing measurements.
   - For maximum hardware isolation, prefer **ECDSA P-256 (`ecdsa-sha2-nistp256`)**, which generates and uses the private key directly inside Android Keystore / StrongBox (TEE / Titan M2).
   - Future releases plan to prefer Android 13+ (API 33+) native JCA/Conscrypt `X25519` and `Ed25519` providers where available.
2. **Project Maturity:**
   - This project is currently an early MVP (`0.1.0`). It has not undergone an independent third-party cryptographic audit.
   - Current live verification has been performed with the Android Emulator (`emulator-5554`) and the Rust bridge (`test-live`); end-to-end testing inside a physical Pixel AVF Debian VM is the next milestone.

## Reporting a Vulnerability

If you discover a security vulnerability in the `PSA1` protocol, the Android app, or the Rust bridge, please report it privately via GitHub Security Advisories at:

https://github.com/moses70/pixel-ssh-agent/security/advisories/new

Please do **not** open a public GitHub issue for undisclosed security vulnerabilities.
