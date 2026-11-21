# Pixel SSH Agent

Ein *from scratch* entwickelter **SSH-Agent für Android**, speziell gebaut für das eingebaute **Pixel Linux Terminal (Debian-VM via AVF)**.

Die privaten SSH-Schlüssel bleiben auf der Android-Seite (Hardware-Keystore / StrongBox für ECDSA P-256, Keystore-AES-GCM-verschlüsselt für Ed25519) und werden bei Bedarf per Biometrie freigegeben. Die Debian-VM erhält lediglich eine leichtgewichtige **Rust-Bridge**, die einen regulären `SSH_AUTH_SOCK` bereitstellt.

## Projektstruktur

- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — Vollständige Spezifikation des `PSA1`-Tunnelprotokolls und der SSH-Agent-Nachrichten.
- `android-app/` — Native Android-App (Kotlin + Jetpack Compose, Material 3, Android Keystore, BiometricPrompt, ForegroundService).
- `debian-bridge/` — Schlanker Rust-Daemon (`pixel-ssh-agent-bridge`) ohne externe C-Abhängigkeiten für die Pixel Debian-VM.

## Features (MVP)

- **SSH-Agent-Protokoll from scratch** (`REQUEST_IDENTITIES`, `SIGN_REQUEST`, OpenSSH Key- & Signatur-Wire-Format, SHA-256-Fingerprints, `authorized_keys`-Export)
- **Schlüsseltypen:**
  - `ecdsa-sha2-nistp256` (Android Keystore / StrongBox Hardware-backed)
  - `ssh-ed25519` (Pure-Kotlin RFC 8032, Private Seed mit Android-Keystore-AES-256-GCM geschützt)
- **Verschlüsselter & authentifizierter Tunnel (`PSA1`):**
  - Ephemeres X25519 + 32-Byte Pre-Shared Key (PSK) + HKDF-SHA256 + AES-256-GCM
  - Läuft über das offizielle **AVF Port-Forwarding** auf `127.0.0.1:<port>` (kein offener WLAN-Port)
- **Biometrische Freigabe:** Konfigurierbare Bestätigung pro Schlüssel (mit optionalem Unlock-Zeitfenster)
