# Pixel SSH Agent — Wire Protocol Specification (`PSA1`)

Dieses Dokument beschreibt das vollständige Protokoll zwischen dem **Debian Bridge-Daemon** (läuft in der Pixel Linux Terminal VM) und der **Android SSH-Agent App** (läuft auf dem Android-Host).

## Architekturübersicht (Option B: Reverse TCP über AVF-Portweiterleitung)

```text
[Debian VM (AVF)]                                   [Android Host]
ssh / git / scp
   │  (OpenSSH Agent Protocol über Unix Socket)
   ▼
pixel-ssh-agent-bridge (Rust)
   │  Lauscht auf TCP 0.0.0.0:22999
   │  ◄──── AVF Port Forwarding (127.0.0.1:22999) ────►
   │                                                 Android App (Kotlin)
   │                                                 • Verbindet als TCP-Client
   │                                                 • PSA1-Handshake & AES-256-GCM
   │                                                 • OpenSSH Agent Dispatcher
   │                                                 • Android Keystore / StrongBox
   │                                                 • BiometricPrompt Freigabe
```

Warum Option B?
- Die AVF-Portweiterleitung des Pixel Linux Terminals bildet den Guest-Port ausschließlich auf `127.0.0.1` auf dem Android-Host ab (kein offener Port im WLAN).
- Da andere Android-Apps mit `INTERNET`-Berechtigung theoretisch ebenfalls auf `127.0.0.1` verbinden können, erzwingt `PSA1` eine **gegenseitige Authentifizierung + Ende-zu-Ende-Verschlüsselung** über einen einmalig gepairten 32-Byte Pre-Shared Key (PSK).

---

## Schicht 1: Authentifizierter Handshake (`PSA1`)

Alle Ganzzahlen sind **Big-Endian**.

### 1.1 `ClientHello` (Android → Debian, 72 Bytes)

| Offset | Länge | Feld             | Beschreibung |
|--------|-------|------------------|--------------|
| 0      | 4     | `magic`          | ASCII `"PSA1"` (`0x50 0x53 0x41 0x31`) |
| 4      | 2     | `version`        | `0x0001` |
| 6      | 2     | `flags`          | `0x0000` (reserviert) |
| 8      | 32    | `client_eph_pub` | Ephemerer X25519 Public Key (RFC 7748) |
| 40     | 32    | `client_nonce`   | 32 zufällige Bytes |

### 1.2 `ServerHello` (Debian → Android, 104 Bytes)

| Offset | Länge | Feld             | Beschreibung |
|--------|-------|------------------|--------------|
| 0      | 4     | `magic`          | ASCII `"PSA1"` |
| 4      | 2     | `version`        | `0x0001` |
| 6      | 2     | `flags`          | `0x0000` |
| 8      | 32    | `server_eph_pub` | Ephemerer X25519 Public Key (RFC 7748) |
| 40     | 32    | `server_nonce`   | 32 zufällige Bytes |
| 72     | 32    | `server_mac`     | `HMAC-SHA256(auth_key, "PSA1-server-auth" \|\| transcript)` |

### 1.3 Schlüsselableitung (beide Seiten)

- `shared_secret = X25519(my_eph_priv, peer_eph_pub)` (32 Bytes; All-Zero-Ergebnis MUSS verworfen werden!)
- `transcript = client_hello[0..72] || server_hello[0..72]` (144 Bytes)
- `salt = SHA-256(transcript)` (32 Bytes)
- `ikm = psk[0..32] || shared_secret[0..32]` (64 Bytes)
- `prk = HKDF-Extract(salt, ikm)` (RFC 5869 mit HMAC-SHA256)
- `auth_key = HKDF-Expand(prk, "PSA1-auth", 32)`
- `c2s_key  = HKDF-Expand(prk, "PSA1-c2s-key", 32)` (Android → Debian)
- `s2c_key  = HKDF-Expand(prk, "PSA1-s2c-key", 32)` (Debian → Android)

### 1.4 `ClientFinish` (Android → Debian, 32 Bytes)

Android verifiziert zunächst `server_mac` (konstantzeitlich). Nur bei Erfolg sendet Android:
- `client_mac = HMAC-SHA256(auth_key, "PSA1-client-auth" || transcript)` (32 Bytes)

Debian verifiziert `client_mac` (konstantzeitlich) und schließt bei Fehler sofort die Verbindung.

---

## Schicht 2: Verschlüsseltes Record-Framing

Nach erfolgreichem Handshake werden alle Daten als AES-256-GCM Records übertragen:

| Feld             | Länge | Beschreibung |
|------------------|-------|--------------|
| `ciphertext_len` | 4     | `uint32_be`, Länge von `ciphertext` inkl. 16-Byte GCM-Tag (min. `16`, max. `1_048_576`) |
| `ciphertext`     | N     | `AES-256-GCM-Seal(key, nonce, plaintext, aad)` |

- **Nonce (12 Bytes, implizit):** `0x00000000 || uint64_be(seq)`
  - Jede Richtung startet mit `seq = 0` und inkrementiert streng um `+1` pro Record.
  - Bei Erreichen von `u64::MAX` wird die Verbindung geschlossen.
- **AAD (12 Bytes):** `uint32_be(ciphertext_len) || uint64_be(seq)`

---

## Schicht 3: Multiplexed Tunnel-Frames (Plaintext im Record)

| Offset | Länge | Feld         | Beschreibung |
|--------|-------|--------------|--------------|
| 0      | 1     | `frame_type` | Typ des Frames |
| 1      | 4     | `channel_id` | `uint32_be` Kanal-ID (`0` für `PING`/`PONG`) |
| 5      | var   | `payload`    | Nutzdaten |

### Frame-Typen

| Wert   | Name    | Richtung | Bedeutung |
|--------|---------|----------|-----------|
| `0x01` | `OPEN`  | Debian → Android | Neuer lokaler SSH-Client hat sich am Unix-Socket verbunden |
| `0x02` | `DATA`  | Bidirektional | Enthält genau **eine vollständige SSH-Agent-Nachricht** (`msg_type \|\| body`, ohne 4-Byte-Längenpräfix) |
| `0x03` | `CLOSE` | Bidirektional | Kanal `channel_id` schließen |
| `0x04` | `PING`  | Bidirektional | Keepalive-Anfrage (`channel_id = 0`) |
| `0x05` | `PONG`  | Bidirektional | Keepalive-Antwort (`channel_id = 0`) |

---

## Schicht 4: OpenSSH Agent Protocol (`draft-miller-ssh-agent`)

Auf dem Unix-Socket spricht `ssh` das Standard-OpenSSH-Agent-Protokoll (`[uint32_be len][byte msg_type][body]`).
Die Debian-Bridge entfernt das äußere 4-Byte-Längenfeld und verpackt `[msg_type][body]` in ein `DATA`-Frame.

### Unterstützte Nachrichten (MVP)

| Typ | Konstante | Richtung | Beschreibung |
|-----|-----------|----------|--------------|
| 5   | `SSH_AGENT_FAILURE` | Agent → Client | Fehler oder Ablehnung (z. B. Biometrie abgebrochen) |
| 6   | `SSH_AGENT_SUCCESS` | Agent → Client | Erfolg |
| 11  | `SSH_AGENTC_REQUEST_IDENTITIES` | Client → Agent | Liste aller verfügbaren Public Keys anfordern |
| 12  | `SSH_AGENT_IDENTITIES_ANSWER` | Agent → Client | `uint32 nkeys`, gefolgt von `nkeys × (string key_blob, string comment)` |
| 13  | `SSH_AGENTC_SIGN_REQUEST` | Client → Agent | `string key_blob`, `string data`, `uint32 flags` |
| 14  | `SSH_AGENT_SIGN_RESPONSE` | Agent → Client | `string signature_blob` |

### Unterstützte Schlüsseltypen

1. **`ecdsa-sha2-nistp256`** (Hardware-backed via Android Keystore / StrongBox)
   - Public Key Blob: `string("ecdsa-sha2-nistp256") || string("nistp256") || string(0x04 || X[32] || Y[32])`
   - Signature Blob: `string("ecdsa-sha2-nistp256") || string(mpint(r) || mpint(s))`
2. **`ssh-ed25519`** (Pure-Kotlin RFC 8032, Private Seed verschlüsselt im Android Keystore AES-256-GCM)
   - Public Key Blob: `string("ssh-ed25519") || string(pub[32])`
   - Signature Blob: `string("ssh-ed25519") || string(sig[64])`
