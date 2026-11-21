# Technical Background: How Pixel SSH Agent Works Under the Hood

This guide explains the core systems, networking, and cryptographic concepts behind **Pixel SSH Agent**—from OpenSSH's binary wire format and Android Keystore internals to modern authenticated encryption and cross-language protocol verification.

---

## 1. What Does an SSH Agent Actually Do?

When you run `ssh user@server`, you must prove possession of a private key **without ever transmitting that key**.

Without an agent, `ssh` reads `~/.ssh/id_ed25519` directly from disk. **With an agent**, the private key stays isolated in a separate process—or in our case, on the Android host inside a hardware security module:

```text
ssh client (Debian)            SSH Agent (Android)             SSH Server
       │                               │                            │
       │◄────────────── Session ID & challenge data ───────────────►│
       │                               │                            │
       ├── 1. REQUEST_IDENTITIES ─────►│                            │
       │◄─ 2. List of public keys ─────┤                            │
       │                               │                            │
       ├────────────── "I have Public Key X" ──────────────────────►│
       │◄───────────── "Prove it: sign this payload" ───────────────┤
       │                               │                            │
       ├── 3. SIGN_REQUEST(Key, Data)─►│  (BiometricPrompt +        │
       │                               │   AndroidKeyStore signing) │
       │◄─ 4. SIGN_RESPONSE(Sig) ──────┤                            │
       │                               │                            │
       ├────────────── Send signature ─────────────────────────────►│
       │◄───────────── Access granted! ─────────────────────────────┤
```

**Key takeaway:** An SSH agent is purely a *signing oracle*. The Debian VM never sees private key bytes—it only sends a challenge in and receives a signature back.

---

## 2. The OpenSSH Binary Wire Format (RFC 4251 & `draft-miller-ssh-agent`)

OpenSSH does not use JSON or HTTP; it uses a compact **big-endian binary format** (RFC 4251). On `SSH_AUTH_SOCK`, every message starts with a 4-byte length prefix:

```text
+-------------------+------------+------------------------+
| uint32 length (N) | byte type  | body (N - 1 bytes)     |
+-------------------+------------+------------------------+
```

The three primitive data types implemented in [`SshWire.kt`](../android-app/app/src/main/java/io/github/moses70/pixelsshagent/ssh/SshWire.kt) are:

1. **`uint32`**: 4 bytes, big-endian (most significant byte first).
2. **`string`** (really an *arbitrary byte array*): `uint32(len)` followed by `len` raw bytes (not null-terminated).
3. **`mpint`** (*Multi-Precision Integer*, signed arbitrary-precision integer):
   - Stored as a `string` in minimal two's-complement big-endian representation.
   - **Classic pitfall:** If a positive integer has its most significant bit set (e.g. `0x80` = binary `10000000`), two's complement would interpret it as negative. Therefore a single `0x00` byte **must** be prepended:
     - `0` → `00 00 00 00` (0 bytes)
     - `0x80` → `00 00 00 02 00 80` (2 bytes: `0x00`, `0x80`)
   - In Java/Kotlin, `BigInteger.toByteArray()` naturally follows this rule for non-negative values.

### Anatomy of an `authorized_keys` Entry
A line like `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... pixel@debian` is simply the Base64-encoded SSH wire public key blob:
- `string("ssh-ed25519")` (`00 00 00 0b "ssh-ed25519"`)
- `string(32-byte-pubkey)` (`00 00 00 20 <32 bytes>`)

An OpenSSH **`SHA256:` fingerprint** is simply the SHA-256 digest of that exact binary blob, Base64-encoded *without* trailing `=` padding.

---

## 3. Practical Cryptography: ECDSA P-256 vs. Ed25519

### 3.1 ECDSA P-256 (`ecdsa-sha2-nistp256`) & Android Keystore / StrongBox
- **Hardware-backed key isolation:**
  Pixel devices include both a Trusted Execution Environment (**TEE**) and a dedicated **StrongBox (Titan M2)** security chip. When we generate a key via `KeyPairGenerator.getInstance("EC", "AndroidKeyStore")`, the private key is created **inside hardware** and has no export API. Even root access on Android cannot directly read the raw private key bytes out of StrongBox.
- **Format mismatch between Java/Android and OpenSSH:**
  - Android's `Signature.getInstance("SHA256withECDSA")` outputs **ASN.1 DER**: `0x30 <seq_len> 0x02 <r_len> <r> 0x02 <s_len> <s>`.
  - OpenSSH (RFC 5656) expects: `string("ecdsa-sha2-nistp256") || string(mpint(r) || mpint(s))`.
  - [`SshSignature.kt`](../android-app/app/src/main/java/io/github/moses70/pixelsshagent/ssh/SshSignature.kt) parses the DER structure and re-encodes `(r, s)` as SSH `mpint`s—producing a ~72–74 byte inner signature payload.

### 3.2 Ed25519 (`ssh-ed25519`, RFC 8032) & Envelope Encryption
- **Why Ed25519 is so widely preferred:**
  Classic ECDSA requires a fresh, perfectly uniform random nonce $k$ for every signature. If $k$ is ever reused or biased, the private key can be recovered algebraically. **Ed25519** eliminates that risk with **deterministic nonces**: the 32-byte seed is hashed with `SHA-512` to produce a secret prefix, and `r = SHA-512(prefix || message) mod L`.
- **Why Pure-Kotlin + Envelope Encryption?**
  Hardware Keystore support for Ed25519 varies across Android versions and devices. We implemented RFC 8032 directly in [`Ed25519Pure.kt`](../android-app/app/src/main/java/io/github/moses70/pixelsshagent/crypto/Ed25519Pure.kt) (verified against the official RFC 8032 Section 7.1 test vectors) and protect the 32-byte seed at rest using **envelope encryption**:
  1. A non-exportable `AES-256-GCM` master key lives inside **Android Keystore**.
  2. The Ed25519 seed is encrypted under that master key before touching disk.
  3. On `SIGN_REQUEST`, the seed is decrypted transiently into memory, used to sign, and wiped in a `finally` block (`seed.fill(0)`).

---

## 4. Android Virtualization Framework (AVF) & Reverse TCP

The Pixel Linux Terminal is not a user-space `chroot`—it is a real **Debian virtual machine** running on KVM/`crosvm` via the **Android Virtualization Framework (AVF)**.

### Why Not Share `SSH_AUTH_SOCK` Directly?
- A Unix domain socket exists only inside a single Linux kernel.
- Android and the Debian VM run **two separate kernels**, and Android's SELinux policy blocks cross-app Unix socket sharing anyway.

### Why Reverse TCP via AVF Port Forwarding?
- When a daemon inside Debian binds a high TCP port (`22999`) and you enable forwarding in the Pixel Terminal settings, Android forwards it **exclusively to `127.0.0.1:22999`** on the Android host.
- **No external ports** are opened on Wi-Fi or cellular interfaces, and Android doesn't need to guess dynamic VM gateway IPs or fight inbound firewall rules.
- **The crucial `127.0.0.1` security catch:**
  All Android apps share the loopback interface. Any app holding the ordinary `INTERNET` permission can connect to `127.0.0.1:22999`. Running raw OpenSSH Agent Protocol over localhost TCP would allow malicious apps to query or spoof the agent. **That is why `PSA1` exists.**

---

## 5. Inside `PSA1` — Modern Protocol Design in Practice

[`PSA1`](PROTOCOL.md) combines standard building blocks inspired by TLS 1.3 and Noise:

### 5.1 Ephemeral X25519 + PSK → Forward Secrecy & Mutual Auth
- One-time pairing establishes a random **256-bit Pre-Shared Key (PSK)**.
- Every new TCP connection generates fresh **ephemeral X25519 keypairs** (RFC 7748) and 32-byte random nonces on both sides.
- Both sides compute `shared_secret = X25519(my_priv, peer_pub)` and reject all-zero outputs (`!isAllZero` / `was_contributory()`) to block low-order curve point attacks.
- **Forward secrecy:** Even if the PSK leaks later, previously captured traffic cannot be decrypted because the ephemeral X25519 private keys were discarded right after the handshake.

### 5.2 HKDF-SHA256 & Transcript Binding (RFC 5869)
Raw Diffie-Hellman output must never be used directly as an AES key. Instead, we run **HKDF**:
1. **Extract:** Combines `salt = SHA-256(client_hello || server_hello_header)` with `ikm = psk || shared_secret` into a uniform `prk`.
   - Binding the entire handshake **transcript** into the salt ensures that tampering with *any* header field (version, flags, nonces, public keys) causes key derivation and MAC verification to fail immediately.
2. **Expand (Domain Separation):** Derives three cryptographically independent 256-bit keys:
   - `auth_key` (`"PSA1-auth"`) — handshake MACs only
   - `c2s_key` (`"PSA1-c2s-key"`) — Android → Debian records
   - `s2c_key` (`"PSA1-s2c-key"`) — Debian → Android records

**Why directional keys?** Reusing the same AES-GCM key and sequence counters (`0, 1, 2, ...`) in both directions would cause **nonce reuse**, catastrophically breaking AES-GCM confidentiality and authenticity. Separate directional keys prevent this by construction.

### 5.3 Constant-Time MAC Verification
Both `server_mac` and `client_mac` are checked with constant-time comparisons (`MessageDigest.isEqual` in Kotlin, `subtle::ConstantTimeEq` in Rust) rather than short-circuiting `==`, preventing byte-by-byte timing side-channel leaks.

### 5.4 AES-256-GCM with Implicit Nonces and AAD
Every post-handshake record uses **AEAD** (*Authenticated Encryption with Associated Data*):
- **Implicit nonce (`0x00000000 || seq`):** Both ends maintain strictly synchronized counters (`0, 1, 2, ...`). This saves 12 bytes per record, guarantees uniqueness, and **blocks replay and packet-reordering attacks** (replaying record #3 when the receiver expects `seq = 4` fails GCM verification immediately).
- **AAD (`ciphertext_len || seq`):** Binds the cleartext 4-byte length prefix and sequence number into the authentication tag so framing metadata cannot be forged.

---

## 6. Multiplexing & Concurrency (Kotlin Coroutines ↔ Rust `std::thread`)

Multiple terminal tabs or SSH agent forwarding (`ssh -A`) can open simultaneous connections to `SSH_AUTH_SOCK`.

- **Layer 3 Multiplexing:** Each local Unix socket connection receives a unique `channel_id`. The Debian bridge reads complete SSH agent messages and wraps them in `DATA(channel_id, payload)`.
- **Non-blocking biometric waits:** On Android, `TunnelClient` dispatches each `DATA` frame in its own coroutine so a slow `SIGN_REQUEST` waiting for user fingerprint approval never stalls `PING`/`PONG` keepalives or concurrent `REQUEST_IDENTITIES` calls.
- **Biometric synchronization:** [`AgentCoordinator.kt`](../android-app/app/src/main/java/io/github/moses70/pixelsshagent/service/AgentCoordinator.kt) serializes approval dialogs with a coroutine `Mutex` and suspends the requesting coroutine on a `CompletableDeferred<Boolean>` (60-second timeout) until `BiometricPrompt` resolves.
- **RAII cleanup in Rust:** [`unix_agent.rs`](../debian-bridge/src/unix_agent.rs) uses a `ChannelGuard` implementing `Drop`, guaranteeing that every `channel_id` is unregistered and closed (`TunnelFrame::Close`) regardless of whether `ssh` disconnects cleanly, times out, or errors.

---

## 7. Cross-Language Test Vectors

When implementing the same binary cryptographic protocol in two languages (Kotlin and Rust), subtle bugs—little-endian vs. big-endian mismatches, off-by-one AAD slices, or HKDF salt differences—are easy to introduce.

To eliminate guesswork, both repositories assert the exact same deterministic `PSA1` vector (fixed PSK, RFC 7748 keys, fixed nonces) down to all five 32-byte hex outputs (`authKey`, `c2sKey`, `s2cKey`, `serverMac`, `clientMac`):
- Kotlin: [`CryptoAndTunnelTest.kt`](../android-app/app/src/test/java/io/github/moses70/pixelsshagent/crypto/CryptoAndTunnelTest.kt)
- Rust: [`crypto.rs`](../debian-bridge/src/crypto.rs)

Because both suites agreed bit-for-bit beforehand, the very first live handshake between the Rust binary and the Android Emulator succeeded on the first attempt.
