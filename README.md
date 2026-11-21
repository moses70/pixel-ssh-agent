# Pixel SSH Agent

Ein *from scratch* entwickelter **SSH-Agent für Android**, speziell gebaut für das eingebaute **Pixel Linux Terminal (Debian-VM via Android Virtualization Framework / AVF)**.

Die privaten SSH-Schlüssel bleiben dauerhaft auf der Android-Seite (Hardware-Keystore / StrongBox für ECDSA P-256, Keystore-AES-GCM-verschlüsselt für Ed25519) und werden bei Bedarf per **BiometricPrompt** freigegeben. Die Debian-VM erhält eine schlanke **Rust-Bridge**, die einen regulären `SSH_AUTH_SOCK` bereitstellt.

## Projektstruktur

- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — Vollständige Spezifikation des `PSA1`-Tunnelprotokolls und der SSH-Agent-Nachrichten.
- [`android-app/`](android-app/) — Native Android-App (Kotlin + Jetpack Compose, Material 3, Android Keystore / StrongBox, BiometricPrompt, ForegroundService).
- [`debian-bridge/`](debian-bridge/) — Schlanker Rust-Daemon (`pixel-ssh-agent-bridge`) ohne C-Abhängigkeiten für die Pixel Debian-VM.

## Architektur (Option B: Reverse TCP über AVF-Portweiterleitung)

```text
[Pixel Debian VM]                                     [Android Host]
ssh / git / ssh-add -L
   │  (OpenSSH Agent Protocol über Unix Socket)
   ▼
pixel-ssh-agent-bridge (Rust)
   │  Lauscht auf TCP 0.0.0.0:22999
   │  ◄──── AVF Port-Forwarding (127.0.0.1:22999) ────►
   │                                                  Pixel SSH Agent (Kotlin)
   │                                                  • Verbindet als TCP-Client
   │                                                  • PSA1 Handshake (X25519 + PSK)
   │                                                  • AES-256-GCM Record Framing
   │                                                  • OpenSSH Agent Protocol
   │                                                  • Keystore / StrongBox + Biometrie
```

## Schritt-für-Schritt-Einrichtung

### 1. Android-App bauen & auf dem Pixel installieren

```powershell
cd android-app
.\gradlew.bat testDebugUnitTest assembleDebug
adb install -r app\build\outputs\apk\debug\app-debug.apk
```

### 2. Rust-Bridge im Pixel Linux Terminal (Debian) bauen

Kopiere das Verzeichnis `debian-bridge/` in deine Debian-VM (z. B. über `/mnt/shared` / Downloads) und baue das Binary:

```bash
# Falls Rust noch nicht installiert ist:
sudo apt update && sudo apt install -y cargo rustc

cd ~/debian-bridge
cargo test
cargo build --release

mkdir -p ~/.local/bin
cp target/release/pixel-ssh-agent-bridge ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"
```

> `cargo test` prüft unter anderem denselben deterministischen `PSA1`-Krypto-Testvektor wie die Kotlin-Unit-Tests in `CryptoAndTunnelTest.kt` und garantiert damit Byte-für-Byte-Kompatibilität.

### 3. Pairing & AVF-Portweiterleitung einrichten

1. Öffne **Pixel SSH Agent** auf dem Pixel:
   - Wechsle auf den Tab **Keys** und erzeuge deinen ersten Schlüssel (`ECDSA P-256 (HW)` oder `Ed25519`).
   - Wechsle zurück auf **Tunnel** und tippe auf **Copy Debian Init**.
2. Füge den kopierten Befehl im **Pixel Linux Terminal** ein:
   ```bash
   pixel-ssh-agent-bridge init --port 22999 --psk <64-zeichen-hex>
   ```
3. Starte die Bridge in Debian:
   ```bash
   pixel-ssh-agent-bridge run
   ```
4. **AVF-Portweiterleitung aktivieren:**
   - Das Pixel Linux Terminal meldet den neuen offenen Port `22999` (oder du gibst ihn unter *Terminal-Einstellungen → Port-Steuerung / Portweiterleitung* frei).
   - Android mappt den Port automatisch **nur lokal auf `127.0.0.1:22999`**.
5. Tippe in der Android-App auf **Start Agent** → der Status wechselt auf **Connected to Debian VM**.

### 4. In Debian nutzen & testen

In einer zweiten Shell (oder in `~/.bashrc`):

```bash
eval "$(pixel-ssh-agent-bridge print-env)"

# Public Keys vom Pixel abfragen:
ssh-add -L

# Direkt per SSH verbinden (löst ggf. Biometrie-Prompt auf dem Pixel aus):
ssh user@dein-server
```

Den zugehörigen `authorized_keys`-Eintrag kannst du in der Android-App im Tab **Keys** direkt per Klick auf das Kopieren-Symbol in die Zwischenablage legen.

### 5. Optional: Automatischer Start via `systemd --user`

```bash
mkdir -p ~/.config/systemd/user
cp ~/debian-bridge/systemd/pixel-ssh-agent-bridge.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now pixel-ssh-agent-bridge.service
```

Und in `~/.bashrc` ergänzen:
```bash
if command -v pixel-ssh-agent-bridge >/dev/null 2>&1; then
    eval "$(pixel-ssh-agent-bridge print-env 2>/dev/null)"
fi
```
