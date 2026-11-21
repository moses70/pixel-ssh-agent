# Pixel SSH Agent — Wire Protocol Specification (`PSA1`)

This document specifies the wire protocol between the **Debian Bridge Daemon** (running inside the Pixel Linux Terminal VM) and the **Android SSH Agent App** (running on the Android host).

## Architecture Overview (Reverse TCP via AVF Port Forwarding)

```text
[Debian VM (AVF)]                                   [Android Host]
ssh / git / scp
   │  (OpenSSH Agent Protocol over Unix socket)
   ▼
pixel-ssh-agent-bridge (Rust)
   │  Listens on TCP 0.0.0.0:22999
   │  ◄──── AVF Port Forwarding (127.0.0.1:22999) ────►
   │                                                 Android App (Kotlin)
   │                                                 • Connects as TCP client
   │                                                 • PSA1 handshake & AES-256-GCM
   │                                                 • OpenSSH Agent dispatcher
   │                                                 • Android Keystore / StrongBox
   │                                                 • BiometricPrompt approval
```

Why reverse TCP?
- AVF port forwarding maps the guest TCP port exclusively onto `127.0.0.1` on the Android host (no port exposed on Wi-Fi or cellular interfaces).
- Because any Android app with `INTERNET` permission can technically connect to `127.0.0.1`, `PSA1` enforces **mutual authentication and end-to-end encryption** bound to a one-time paired 32-byte Pre-Shared Key (PSK).

---

## Layer 1: Authenticated Handshake (`PSA1`)

All multi-byte integers are **Big-Endian**.

### 1.1 `ClientHello` (Android → Debian, 72 bytes)

| Offset | Length | Field            | Description |
|--------|--------|------------------|-------------|
| 0      | 4      | `magic`          | ASCII `"PSA1"` (`0x50 0x53 0x41 0x31`) |
| 4      | 2      | `version`        | `0x0001` |
| 6      | 2      | `flags`          | `0x0000` (reserved) |
| 8      | 32     | `client_eph_pub` | Ephemeral X25519 public key (RFC 7748) |
| 40     | 32     | `client_nonce`   | 32 random bytes |

### 1.2 `ServerHello` (Debian → Android, 104 bytes)

| Offset | Length | Field            | Description |
|--------|--------|------------------|-------------|
| 0      | 4      | `magic`          | ASCII `"PSA1"` |
| 4      | 2      | `version`        | `0x0001` |
| 6      | 2      | `flags`          | `0x0000` |
| 8      | 32     | `server_eph_pub` | Ephemeral X25519 public key (RFC 7748) |
| 40     | 32     | `server_nonce`   | 32 random bytes |
| 72     | 32     | `server_mac`     | `HMAC-SHA256(auth_key, "PSA1-server-auth" \|\| transcript)` |

### 1.3 Key Derivation (Both Sides)

- `shared_secret = X25519(my_eph_priv, peer_eph_pub)` (32 bytes; all-zero output MUST be rejected)
- `transcript = client_hello[0..72] || server_hello[0..72]` (144 bytes)
- `salt = SHA-256(transcript)` (32 bytes)
- `ikm = psk[0..32] || shared_secret[0..32]` (64 bytes)
- `prk = HKDF-Extract(salt, ikm)` (RFC 5869 with HMAC-SHA256)
- `auth_key = HKDF-Expand(prk, "PSA1-auth", 32)`
- `c2s_key  = HKDF-Expand(prk, "PSA1-c2s-key", 32)` (Android → Debian)
- `s2c_key  = HKDF-Expand(prk, "PSA1-s2c-key", 32)` (Debian → Android)

### 1.4 `ClientFinish` (Android → Debian, 32 bytes)

Android verifies `server_mac` in constant time. Only on success does Android transmit:
- `client_mac = HMAC-SHA256(auth_key, "PSA1-client-auth" || transcript)` (32 bytes)

Debian verifies `client_mac` in constant time and immediately closes the TCP connection on mismatch.

---

## Layer 2: Encrypted Record Framing

After the handshake completes, all traffic is framed as AES-256-GCM encrypted records:

| Field            | Length | Description |
|------------------|--------|-------------|
| `ciphertext_len` | 4      | `uint32_be`, length of `ciphertext` including 16-byte GCM tag (min `16`, max `1_048_576`) |
| `ciphertext`     | N      | `AES-256-GCM-Seal(key, nonce, plaintext, aad)` |

- **Nonce (12 bytes, implicit):** `0x00000000 || uint64_be(seq)`
  - Each direction starts at `seq = 0` and strictly increments by `+1` per record.
  - Connections MUST terminate before `seq` overflows `u64::MAX`.
- **AAD (12 bytes):** `uint32_be(ciphertext_len) || uint64_be(seq)`

---

## Layer 3: Multiplexed Tunnel Frames (Decrypted Record Plaintext)

| Offset | Length | Field        | Description |
|--------|--------|--------------|-------------|
| 0      | 1      | `frame_type` | Frame type byte |
| 1      | 4      | `channel_id` | `uint32_be` channel identifier (`0` for `PING`/`PONG`) |
| 5      | var    | `payload`    | Frame payload bytes |

### Frame Types

| Value  | Name    | Direction | Meaning |
|--------|---------|-----------|---------|
| `0x01` | `OPEN`  | Debian → Android | A new local SSH client connected to `SSH_AUTH_SOCK` |
| `0x02` | `DATA`  | Bidirectional | Carries exactly **one complete SSH agent message** (`msg_type \|\| body`, without the outer 4-byte length prefix) |
| `0x03` | `CLOSE` | Bidirectional | Close `channel_id` |
| `0x04` | `PING`  | Bidirectional | Keepalive request (`channel_id = 0`) |
| `0x05` | `PONG`  | Bidirectional | Keepalive response (`channel_id = 0`) |

---

## Layer 4: OpenSSH Agent Protocol (`draft-miller-ssh-agent`)

On the Unix domain socket, `ssh` speaks standard framed OpenSSH agent messages (`[uint32_be len][byte msg_type][body]`).
The Debian bridge strips the outer 4-byte length header when encapsulating into `DATA` frames and re-adds it when writing responses back to the Unix socket.

### Supported Messages (MVP)

| Type | Constant | Direction | Description |
|------|----------|-----------|-------------|
| 5    | `SSH_AGENT_FAILURE` | Agent → Client | Error or rejection (e.g. biometric prompt denied) |
| 6    | `SSH_AGENT_SUCCESS` | Agent → Client | Success |
| 11   | `SSH_AGENTC_REQUEST_IDENTITIES` | Client → Agent | Request list of available public keys |
| 12   | `SSH_AGENT_IDENTITIES_ANSWER` | Agent → Client | `uint32 nkeys`, followed by `nkeys × (string key_blob, string comment)` |
| 13   | `SSH_AGENTC_SIGN_REQUEST` | Client → Agent | `string key_blob`, `string data`, `uint32 flags` |
| 14   | `SSH_AGENT_SIGN_RESPONSE` | Agent → Client | `string signature_blob` |
| 27/28 | `SSH_AGENTC_EXTENSION` → `SSH_AGENT_EXTENSION_FAILURE` | Bidirectional | Explicitly advertises unsupported extensions |

### Supported Key Types

1. **`ecdsa-sha2-nistp256`** (Hardware-backed via Android Keystore / StrongBox)
   - Public key blob: `string("ecdsa-sha2-nistp256") || string("nistp256") || string(0x04 || X[32] || Y[32])`
   - Signature blob: `string("ecdsa-sha2-nistp256") || string(mpint(r) || mpint(s))`
2. **`ssh-ed25519`** (Pure-Kotlin RFC 8032, private seed encrypted via Android Keystore AES-256-GCM)
   - Public key blob: `string("ssh-ed25519") || string(pub[32])`
   - Signature blob: `string("ssh-ed25519") || string(sig[64])`
