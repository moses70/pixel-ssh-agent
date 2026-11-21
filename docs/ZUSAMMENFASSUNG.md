# Projekt-Zusammenfassung: Pixel SSH Agent

Diese Zusammenfassung dokumentiert alle Arbeitsschritte, Architekturentscheidungen, Dateien, Git-Commits und Testergebnisse beim Aufbau des **Pixel SSH Agent** – eines *from scratch* entwickelten SSH-Agents für Android, speziell zugeschnitten auf das eingebaute **Pixel Linux Terminal (Debian-VM via AVF)**.

---

## 1. Ziel & gewählte Architektur

Das Ziel war es, SSH-Schlüssel dauerhaft und geschützt auf dem Android-Host (im **Android Keystore / StrongBox** mit optionaler **Biometrie-Freigabe**) zu verwalten, sodass private Schlüssel niemals als Datei in der Debian-VM liegen – während OpenSSH in Debian den Agent völlig transparent über `SSH_AUTH_SOCK` nutzen kann.

### Kernentscheidungen
1. **Verbindungsrichtung — Option B (Reverse TCP via AVF-Portweiterleitung):**
   - Der Rust-Daemon in Debian lauscht auf TCP Port `22999`.
   - Die offizielle AVF-Portweiterleitung des Pixel Linux Terminals mappt diesen Port ausschließlich lokal auf `127.0.0.1:22999` am Android-Host (kein exponierter WLAN-Port).
   - Die Android-App verbindet sich über einen `ForegroundService` als TCP-Client dorthin und hält den verschlüsselten Kanal offen.
2. **Debian-Bridge in Rust (ohne C-Abhängigkeiten):**
   - Reines `std::net` / `std::os::unix::net` / `std::thread` + Pure-Rust-Kryptokrates (`x25519-dalek`, `aes-gcm`, `hkdf`, `hmac`, `sha2`, `subtle`).
   - Kompiliert in ~1 Sekunde ohne `libssl-dev` oder Async-Runtime-Overhead.
3. **MVP-Funktionsumfang:**
   - OpenSSH Agent Protokoll *from scratch* (`REQUEST_IDENTITIES`, `SIGN_REQUEST`, `EXTENSION` → `EXTENSION_FAILURE`).
   - Schlüsseltypen: **ECDSA P-256** (Hardware-backed via Android Keystore / StrongBox) und **Ed25519** (Pure-Kotlin RFC 8032, 32-Byte-Seed via Keystore-AES-256-GCM geschützt).
   - Gegenseitig authentifizierter & verschlüsselter Tunnel (`PSA1`) + konfigurierbare Biometrie-Bestätigung (`BiometricPrompt`).

---

## 2. Übersicht der erstellten Komponenten

### Dokumentation & Spezifikation
- [`README.md`](../README.md) — Projektüberblick, Architektur und Schritt-für-Schritt-Einrichtung (inkl. `systemd --user`).
- [`docs/PROTOCOL.md`](PROTOCOL.md) — Vollständige Byte-genaue Spezifikation aller 4 Protokollschichten (`PSA1`-Handshake, AES-256-GCM Record-Framing, Multiplexed Tunnel-Frames, OpenSSH Agent Protocol).
- [`docs/ZUSAMMENFASSUNG.md`](ZUSAMMENFASSUNG.md) — Dieses Dokument.
- [`docs/TECHNISCHER_HINTERGRUND.md`](TECHNISCHER_HINTERGRUND.md) — Tiefgehende technische Hintergründe und Lernmaterial.

### Android-App (`android-app/`, Kotlin + Jetpack Compose, Material 3)
- **SSH-Protokoll (*from scratch*):**
  - `ssh/SshWire.kt` — RFC 4251 Binär-Codec (`byte`, `uint32`, `string`, `mpint`).
  - `ssh/SshPublicKey.kt` — OpenSSH Public-Key-Blobs (`ecdsa-sha2-nistp256`, `ssh-ed25519`), `authorized_keys`-Export, OpenSSH-`SHA256:`-Fingerprints.
  - `ssh/SshSignature.kt` — ASN.1-DER → OpenSSH-ECDSA-Konverter sowie Ed25519-Signatur-Framing.
  - `ssh/SshAgentProtocol.kt` — `draft-miller-ssh-agent` Dispatcher & Antwort-Encoder.
- **Kryptographie & Keystore:**
  - `crypto/X25519Pure.kt` — Pure-Kotlin RFC 7748 X25519 (Montgomery-Ladder).
  - `crypto/Ed25519Pure.kt` — Pure-Kotlin RFC 8032 Ed25519 (Signieren & Verifizieren).
  - `crypto/TunnelCrypto.kt` — RFC 5869 HKDF-SHA256, `PSA1`-Handshake (Client & Server), AES-256-GCM Record-Session.
  - `crypto/KeyRepository.kt` — Verwaltung von ECDSA P-256 (StrongBox/AndroidKeyStore) und Keystore-verschlüsselten Ed25519-Seeds.
- **Tunnel, Service & Benutzeroberfläche:**
  - `tunnel/TunnelFrame.kt` — Multiplex-Frame-Codec (`OPEN`, `DATA`, `CLOSE`, `PING`, `PONG`).
  - `tunnel/TunnelClient.kt` — Resiliente TCP-Client-Schleife mit exponentiellem Backoff, Keepalive-Pings und parallelem Channel-Dispatching.
  - `service/SettingsStore.kt` & `service/AgentCoordinator.kt` — Persistente Pairing-Konfiguration, Aktivitäts-Log, Biometrie-Unlock-Zeitfenster und Koordination ausstehender Signaturanfragen.
  - `service/AgentForegroundService.kt` — Android-`ForegroundService` (`specialUse`) mit Status- und Signaturanfrage-Benachrichtigungen.
  - `ui/MainActivity.kt` — Material-3-Oberfläche (Dynamic Color) mit Tabs für **Tunnel & Pairing** (inkl. „Copy Debian Init“), **Keys** (Erstellen, `authorized_keys` kopieren, Löschen) und **Log**, plus `BiometricPrompt`-Integration.
- **Unit-Tests:**
  - `test/.../ssh/SshProtocolTest.kt` & `test/.../crypto/CryptoAndTunnelTest.kt`.

### Rust Debian-Bridge (`debian-bridge/`)
- `Cargo.toml` — Pure-Rust-Abhängigkeiten, optimiertes Release-Profil (`opt-level = "s"`, `lto = true`, `strip = true`).
- `src/crypto.rs` — Byte-identische Server-Seite von `PSA1` (X25519, HKDF-SHA256, konstantzeitliche HMAC-Prüfung, AES-256-GCM Records) + Cross-Language-Unit-Tests.
- `src/tunnel.rs` — Multiplexed `TunnelFrame`-Codec, `BridgeHub` & `ActiveTunnel` für gleichzeitige SSH-Clients und saubere Reconnect-Ablösung.
- `src/unix_agent.rs` — Unix-Domain-Socket-Server (`SSH_AUTH_SOCK`, Rechte `0600`) mit OpenSSH-Frame-Weiterleitung und RAII-`ChannelGuard`.
- `src/config.rs` — Konfigurationsspeicher (`~/.config/pixel-ssh-agent/config.env`, Rechte `0600`) & PSK-Generator.
- `src/main.rs` — CLI mit `init`, `run`, `print-env` sowie dem plattformübergreifenden Live-Integrationstest `test-live`.
- `systemd/pixel-ssh-agent-bridge.service` — Fertige `systemd --user`-Unit für automatischen Start in Debian.

---

## 3. Lokale Git-Commit-Historie

Alle Meilensteine wurden fortlaufend als atomare lokale Commits im Branch `main` gesichert:

| Commit | Beschreibung |
|--------|--------------|
| `15dbd4b` | Repository-Initialisierung, `.gitignore`, `README.md` und `PSA1`-Spezifikation (`docs/PROTOCOL.md`) |
| `9b2887b` | Android-Gradle-Gerüst (AGP 9.4.1 / Kotlin 2.4.21 / Compose) + SSH-Wire- & Agent-Protokoll + Unit-Tests |
| `e23ae14` | Pure-Kotlin X25519, Ed25519, `PSA1`-Tunnel-Krypto, Multiplex-Client & RFC-Testvektoren |
| `a97260a` | Keystore/StrongBox `KeyRepository`, `AgentForegroundService`, Biometrie-Gate & Material-3-UI |
| `a2ea813` | Rust `debian-bridge` (`PSA1`-Server, Unix `SSH_AUTH_SOCK`-Bridge, CLI & `systemd`-Service) |
| `9d20371` | Vollständige Installations-, Pairing- und Nutzungsanleitung in `README.md` |
| `7e38054` | Plattformübergreifendes `test-live`-Integrationskommando in `debian-bridge` |

---

## 4. Verifikation & Live-Testergebnisse

### Automatisierte Tests (JVM / Android)
- **`.\gradlew.bat testDebugUnitTest assembleDebug`:** Warnungsfrei gebaut (`app-debug.apk`), alle Unit-Tests bestanden:
  - RFC 4251 `mpint`-Beispiele & OpenSSH-Key-/Signatur-Blobs
  - RFC 7748 Section 6.1 X25519-Testvektor
  - RFC 8032 Section 7.1 Ed25519-Testvektoren (TEST 1, 2, 3)
  - RFC 5869 HKDF-SHA256 Test Case 1
  - Zurückweisung falscher PSKs im Handshake
  - Deterministischer Cross-Language-`PSA1`-Schlüsselableitungsvektor
  - End-to-End-Loopback-TCP-Tunnel mit echter Ed25519-SSH-Signatur

### Automatisierte Tests (Rust)
- **`cargo test` (Windows, `rustc 1.100.0`):** Alle 3 Unit-Tests warnungsfrei bestanden:
  - `tunnel::tests::tunnel_frame_roundtrip`
  - `crypto::tests::encrypted_record_roundtrip_and_tamper_detection`
  - `crypto::tests::psa1_cross_language_key_derivation_matches_kotlin` (identische Hex-Ergebnisse wie in Kotlin!)

### Live-Integrationstest gegen den laufenden Android-Emulator (`emulator-5554`)
- APK auf `emulator-5554` installiert und gestartet, Port `22999` per `adb reverse tcp:22999 tcp:22999` durchgereicht.
- Im Emulator wurde ein Hardware-Key (`ecdsa-sha2-nistp256`, Kommentar `pixel@emu`) angelegt, der PSK per **Copy Debian Init** übernommen und der `ForegroundService` gestartet.
- Ergebnis von `pixel-ssh-agent-bridge.exe test-live`:
  - `PSA1` gegenseitige Authentifizierung & X25519/HKDF-Handshake: **PASS**
  - Verschlüsseltes Ping/Pong-Keepalive: **PASS**
  - `REQUEST_IDENTITIES`: **PASS** (`ecdsa-sha2-nistp256`, `pixel@emu`)
  - `SIGN_REQUEST` nach Nutzerfreigabe in der App: **PASS** (`SIGN_RESPONSE`, `ecdsa-sha2-nistp256`, 73 Bytes)

---

## 5. Mögliche nächste Ausbaustufen (Post-MVP)
- **Kryptografische Signaturprüfung in `test-live`:** Den erhaltenen ECDSA-/Ed25519-Signatur-Blob im Rust-Test direkt gegen den gelieferten Public Key verifizieren.
- **Weitere SSH-Agent-Kommandos:** `SSH_AGENTC_LOCK` / `UNLOCK`, RSA-SHA2 (`rsa-sha2-256`/`512`) oder Import bestehender OpenSSH-Private-Keys.
- **Komfort:** QR-Code-Pairing, Anzeige des Ziel-Hosts/Session-Infos (über OpenSSH `session-bind@openssh.com` Extension) direkt im Biometrie-Prompt.
- **Deployment auf echtem Pixel:** `debian-bridge` direkt in der Pixel-Debian-VM kompilieren und per `systemd --user` dauerhaft betreiben.
