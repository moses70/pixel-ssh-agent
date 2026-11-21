# Technischer Hintergrund: Wie der Pixel SSH Agent unter der Haube funktioniert

Dieses Dokument erklärt die wichtigsten Konzepte hinter unserem Projekt – von den Tiefen des OpenSSH-Binärprotokolls über moderne Kryptographie bis hin zur Android-Virtualisierung und sicherem Protokolldesign.

---

## 1. Was macht ein SSH-Agent eigentlich?

Wenn du `ssh user@server` ausführst, sollst du beweisen, dass du im Besitz eines privaten Schlüssels bist – **ohne diesen Schlüssel jemals zu übertragen**.

Ohne Agent liest `ssh` die Datei `~/.ssh/id_ed25519` selbst ein. **Mit Agent** bleibt der private Schlüssel in einem eigenen Prozess (oder wie bei uns: auf dem Android-Host im Hardware-Sicherheitschip!):

```text
ssh-Client (Debian)            SSH-Agent (Android)             SSH-Server
       │                               │                            │
       │◄────────────── Session-ID & Challenge-Daten ──────────────►│
       │                               │                            │
       ├── 1. REQUEST_IDENTITIES ─────►│                            │
       │◄─ 2. Liste der Public Keys ───┤                            │
       │                               │                            │
       ├────────────── "Ich habe Public Key X" ────────────────────►│
       │◄───────────── "Ok, dann signiere diese Daten!" ────────────┤
       │                               │                            │
       ├── 3. SIGN_REQUEST(Key, Data)─►│  (Biometrie-Prompt +       │
       │                               │   Signatur im Keystore)    │
       │◄─ 4. SIGN_RESPONSE(Sig) ──────┤                            │
       │                               │                            │
       ├────────────── Signatur senden ────────────────────────────►│
       │◄───────────── Login erlaubt! ──────────────────────────────┤
```

**Merksatz:** Ein SSH-Agent ist ein reines *Signier-Orakel*. Die Debian-VM erfährt niemals die privaten Schlüsselbytes – sie schickt nur Daten hinein und bekommt eine Signatur zurück.

---

## 2. Das OpenSSH-Binärprotokoll (RFC 4251 & `draft-miller-ssh-agent`)

SSH verwendet kein JSON und kein HTTP, sondern ein extrem kompaktes **Big-Endian-Binärformat** (RFC 4251). Auf dem Unix-Socket beginnt jede Nachricht mit ihrer 4-Byte-Länge:

```text
+-------------------+------------+------------------------+
| uint32 length (N) | byte type  | body (N - 1 bytes)     |
+-------------------+------------+------------------------+
```

Die drei wichtigsten Grundtypen, die wir in [`SshWire.kt`](../android-app/app/src/main/java/dev/pixelsshagent/ssh/SshWire.kt) selbst implementiert haben:

1. **`uint32`**: 4 Bytes, Big-Endian (höchstwertiges Byte zuerst).
2. **`string`** (eigentlich *beliebiges Byte-Array*): `uint32(len)` gefolgt von genau `len` Bytes. Auch Textstrings sind nicht nullterminiert!
3. **`mpint`** (*Multi-Precision Integer*, vorzeichenbehaftete Großzahl):
   - Wird als `string` gespeichert, minimal im Zweierkomplement.
   - **Klassische Stolperfalle:** Wenn eine positive Zahl im höchsten Bit des ersten Bytes eine `1` hat (z. B. `0x80` = binär `10000000`), würde sie im Zweierkomplement wie eine negative Zahl aussehen! Deshalb **muss** ein einzelnes `0x00`-Byte vorangestellt werden:
     - `0` → `00 00 00 00` (0 Bytes)
     - `0x80` → `00 00 00 02 00 80` (2 Bytes: `0x00`, `0x80`)
   - In Java/Kotlin liefert `BigInteger.toByteArray()` genau diese Darstellung (solange der Wert nicht negativ ist).

### Warum sieht ein Public Key in `~/.ssh/authorized_keys` so aus?
Eine Zeile wie `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... pixel@debian` ist gar kein geheimes Spezialformat: Der mittlere Teil ist einfach das **Base64-kodierte SSH-Wire-Blob**:
- `string("ssh-ed25519")` (`00 00 00 0b "ssh-ed25519"`)
- `string(32-byte-pubkey)` (`00 00 00 20 <32 bytes>`)

Der **OpenSSH-Fingerprint** (`SHA256:...`) ist schlicht der SHA-256-Hash über exakt dieses binäre Blob, Base64-kodiert *ohne* abschließendes `=`.

---

## 3. Kryptographie in der Praxis: ECDSA P-256 vs. Ed25519

### 3.1 ECDSA P-256 (`ecdsa-sha2-nistp256`) & Android Keystore / StrongBox
- **Warum Hardware-Keystore?**
  Auf Pixel-Geräten gibt es neben der normalen CPU eine isolierte Sicherheitsumgebung (**TEE** = Trusted Execution Environment) und zusätzlich den dedizierten Sicherheitschip **StrongBox (Titan M2)**.
  Wenn wir mit `KeyPairGenerator.getInstance("EC", "AndroidKeyStore")` einen Schlüssel erzeugen, wird der private Schlüssel **im Chip generiert** und kann per API nicht ausgelesen werden. Selbst Root-Zugriff auf das Android-OS kann die Schlüsselbytes nicht direkt aus der Hardware extrahieren.
- **Der Format-Unterschied zwischen Java/Android und OpenSSH:**
  - Androids `Signature.getInstance("SHA256withECDSA")` liefert eine **ASN.1-DER**-Struktur: `0x30 <seq_len> 0x02 <r_len> <r> 0x02 <s_len> <s>`.
  - OpenSSH (RFC 5656) will aber **kein DER**, sondern:
    `string("ecdsa-sha2-nistp256") || string(mpint(r) || mpint(s))`.
  - Genau diese Umwandlung macht [`SshSignature.kt`](../android-app/app/src/main/java/dev/pixelsshagent/ssh/SshSignature.kt). Und genau darum hatte unsere Live-Signatur im Emulator `73 Bytes` (`4 + 32/33 Bytes` für `r` + `4 + 32/33 Bytes` für `s`).

### 3.2 Ed25519 (`ssh-ed25519`, RFC 8032) & Envelope Encryption
- **Warum ist Ed25519 so beliebt?**
  Bei klassischem ECDSA braucht jede Signatur eine perfekt zufällige Einmalzahl $k$. Wiederholt sich $k$ auch nur einmal (oder ist leicht vorhersagbar), lässt sich der private Schlüssel mathematisch sofort berechnen!
  **Ed25519** löst das durch **deterministische Nonces**: Aus dem 32-Byte-Seed wird über `SHA-512` ein geheimer Präfix abgeleitet und zusammen mit der Nachricht gehasht (`r = SHA-512(prefix || M) mod L`). Gleicher Key + gleiche Nachricht = immer exakt dieselbe Signatur, ohne Risiko eines schlechten Zufallszahlengenerators.
- **Warum Pure-Kotlin + Envelope Encryption?**
  Android-Hardware-Keystores unterstützen Ed25519 historisch nicht flächendeckend auf allen API-Stufen/Geräten. Deshalb haben wir RFC 8032 direkt in [`Ed25519Pure.kt`](../android-app/app/src/main/java/dev/pixelsshagent/crypto/Ed25519Pure.kt) in ~150 Zeilen Kotlin umgesetzt (verifiziert gegen die offiziellen RFC-8032-Testvektoren!).
  Damit der 32-Byte-Seed trotzdem nicht im Klartext auf dem Flash-Speicher liegt, nutzen wir **Envelope Encryption**:
  1. Ein Master-Schlüssel (`AES-256-GCM`) lebt untrennbar im **Android Keystore**.
  2. Der Ed25519-Seed wird mit diesem Master-Key verschlüsselt und nur als Chiffretext gespeichert.
  3. Erst beim Signieren wird der Seed kurz im RAM entschlüsselt, signiert und im `finally`-Block sofort mit Nullen überschrieben (`seed.fill(0)`).

---

## 4. Android Virtualization Framework (AVF) & warum Option B?

Das Pixel Linux Terminal ist kein einfacher `chroot` wie Termux, sondern eine echte **Linux-VM (Debian)**, die über KVM/`crosvm` im **Android Virtualization Framework (AVF)** läuft.

### Warum geht `SSH_AUTH_SOCK` nicht direkt?
- Ein Unix-Domain-Socket existiert nur innerhalb *eines* Linux-Kernels.
- Android-Host und Debian-VM haben **zwei getrennte Kernel**! Zudem blockiert Androids SELinux den Dateisystem-Austausch von Sockets zwischen Apps.

### Warum Reverse-TCP über AVF-Portweiterleitung („Option B“)?
- Wenn ein Prozess in der Debian-VM auf einem Port (`22999`) lauscht und du diesen in den Pixel-Terminal-Einstellungen freigibst, richtet Android eine Weiterleitung ein, die den Port **ausschließlich auf `127.0.0.1:22999`** am Android-Host bindet.
- **Vorteil 1:** Kein Port ist im WLAN oder Mobilfunknetz offen.
- **Vorteil 2:** Die Android-App muss keine dynamische VM-Bridge-IP erraten und kämpft nicht mit Android-Firewall-Regeln für eingehende Pakete.
- **Der entscheidende Sicherheits-Haken an `127.0.0.1`:**
  Auf Android teilen sich alle Apps denselben Loopback-Adapter (`127.0.0.1`). **Jede** installierte App mit der Standard-Berechtigung `INTERNET` könnte sich also theoretisch auf `127.0.0.1:22999` verbinden!
  Würde dort das ungeschützte SSH-Agent-Protokoll laufen, könnte eine fremde App auf dem Handy versuchen, SSH-Signaturen anzufordern oder sich als Debian-VM auszugeben. **Genau deshalb existiert `PSA1`.**

---

## 5. Sicherheitsdesign von `PSA1` — moderne Kryptographie am konkreten Beispiel

Unser Tunnelprotokoll [`PSA1`](PROTOCOL.md) kombiniert mehrere bewährte Bausteine moderner Protokolle (ähnlich wie TLS 1.3 oder Noise):

### 5.1 Ephemeres X25519 + PSK → Forward Secrecy & gegenseitige Authentifizierung
- Beim Pairing teilen beide Seiten einen zufälligen **256-Bit Pre-Shared Key (PSK)**.
- Bei *jeder* neuen TCP-Verbindung erzeugen Android und Debian zusätzlich frische **ephemere X25519-Schlüsselpaare** (Elliptische-Kurven-Diffie-Hellman auf Curve25519, RFC 7748) sowie 32-Byte-Zufalls-Nonces.
- Daraus entsteht ein gemeinsames Sitzungsgeheimnis `shared_secret = X25519(priv, peer_pub)`.
  - *Sicherheitsdetail:* Wir prüfen explizit, dass `shared_secret` nicht aus 32 Null-Bytes besteht (`!isAllZero` / `was_contributory()`), um Angriffe mit manipulierten *Low-Order-Punkten* abzuwehren.
- **Forward Secrecy:** Selbst wenn jemand später den PSK stiehlt, kann er aufgezeichneten Datenverkehr früherer Sessions nicht nachträglich entschlüsseln, weil die ephemeren X25519-Privatschlüssel nach dem Handshake sofort verworfen wurden.

### 5.2 HKDF-SHA256 & Transcript-Binding (RFC 5869)
Man darf rohes Diffie-Hellman-Material niemals direkt als AES-Schlüssel verwenden! Stattdessen nutzen wir **HKDF (HMAC-based Key Derivation Function)** in zwei Phasen:
1. **Extract:** Mischt `salt = SHA-256(client_hello || server_hello_header)` mit `ikm = psk || shared_secret` zu einem gleichmäßig zufälligen `prk`.
   - Weil der gesamte Handshake-Text (*Transcript*) im Salt steckt, führt **jede noch so kleine Manipulation** am Magic, an der Version, den Nonces oder den Public Keys sofort zu völlig anderen Schlüsseln!
2. **Expand (Domain Separation):** Aus `prk` leiten wir drei strikt getrennte Schlüssel ab:
   - `auth_key` (`"PSA1-auth"`) → nur für die Handshake-HMACs
   - `c2s_key` (`"PSA1-c2s-key"`) → nur für Daten Android → Debian
   - `s2c_key` (`"PSA1-s2c-key"`) → nur für Daten Debian → Android

**Warum zwei getrennte Richtungsschlüssel?** Würden beide Seiten denselben AES-GCM-Schlüssel mit denselben Sequenznummern (`0, 1, 2, ...`) nutzen, entstünde **Nonce-Reuse** – bei AES-GCM ein totaler Sicherheitsbruch (Klartext-XOR & Verlust der Authentizität)! Durch getrennte Richtungsschlüssel ist Nonce-Reuse ausgeschlossen.

### 5.3 Konstantzeitlicher Vergleich gegen Timing-Angriffe
Bei der Prüfung von `server_mac` und `client_mac` nutzen wir niemals normales `==`:
- Ein normales `==` bricht beim ersten ungleichen Byte ab. Ein Angreifer könnte durch präzise Zeitmessung Byte für Byte erraten.
- Deshalb nutzen wir `MessageDigest.isEqual(...)` (Kotlin/Java) und `subtle::ConstantTimeEq` (Rust), die immer alle 32 Bytes durchlaufen.

### 5.4 AES-256-GCM mit impliziter Nonce und AAD
Nach dem Handshake wird jede Nachricht als **AEAD-Record** (*Authenticated Encryption with Associated Data*) übertragen:
- **Implizite Nonce (`0x00000000 || seq`):** Statt 12 Bytes Zufall pro Paket zu senden, zählen Sender und Empfänger einfach streng synchron `seq = 0, 1, 2, ...`.
  - Spart Bandbreite, garantiert Einmaligkeit **und verhindert Replay- sowie Reordering-Angriffe**: Spielt ein Angreifer Paket #3 nochmal ein, erwartet der Empfänger `seq = 4` → AES-GCM lehnt das Paket sofort ab!
- **AAD (`ciphertext_len || seq`):** Die unverschlüsselte 4-Byte-Längenangabe am Paketkopf wird als *Associated Data* in den GCM-Authentifizierungstag einbezogen. Ein Angreifer kann also nicht einmal die Längenangabe manipulieren, ohne dass die Entschlüsselung fehlschlägt.

---

## 6. Multiplexing & Nebenläufigkeit (Kotlin ↔ Rust)

Was passiert, wenn du in Debian zwei Terminal-Tabs offen hast und in beiden gleichzeitig `ssh` startest? Oder wenn `ssh -A` (Agent Forwarding) mehrere Anfragen verschachtelt?

Deshalb gibt es **Schicht 3 (Tunnel-Frames)**:
- Jeder lokale Unix-Client am `SSH_AUTH_SOCK` bekommt eine eindeutige `channel_id` (`1, 2, 3, ...`).
- Die Debian-Bridge liest auf dem Unix-Socket immer vollständige SSH-Agent-Frames und verpackt sie in `DATA(channel_id, payload)`.
- Auf Android startet `TunnelClient` pro `DATA`-Frame eine eigene Coroutine (`scope.launch(Dispatchers.IO)`), sodass ein langsamer `SIGN_REQUEST` (der gerade auf deinen Fingerabdruck wartet!) nicht den gesamten Tunnel oder Ping/Pong-Keepalives blockiert.
- **Synchronisierung der Biometrie:** In [`AgentCoordinator.kt`](../android-app/app/src/main/java/dev/pixelsshagent/service/AgentCoordinator.kt) serialisiert ein Coroutine-`Mutex` (`approvalMutex`) parallele Signatur-Prompts, und ein `CompletableDeferred<Boolean>` pausiert exakt die anfragende Coroutine (mit 60s Timeout), bis der `BiometricPrompt` im UI-Thread `approved = true/false` zurückmeldet.
- **RAII / `Drop`-Guard in Rust:** In [`unix_agent.rs`](../debian-bridge/src/unix_agent.rs) sorgt ein kleines `struct ChannelGuard` mit `impl Drop` dafür, dass beim Beenden eines `ssh`-Prozesses (egal ob normal per EOF, per Fehler oder Timeout) der Kanal *garantiert* aus der `HashMap` entfernt und ein `CLOSE`-Frame an Android geschickt wird.

---

## 7. Cross-Language-Testvektoren — der wichtigste Trick bei eigenen Protokollen

Wenn man zwei völlig getrennte Implementierungen desselben binären Kryptoprotokolls schreibt (Kotlin auf Android + Rust auf Debian), sind subtile Unterschiede extrem häufig:
- Little-Endian vs. Big-Endian (z. B. X25519 ist Little-Endian, SSH und `PSA1`-Header sind Big-Endian!)
- Vergessenes AAD-Feld oder andere Reihenfolge im Transcript
- Unterschiedliche HKDF-Salt-Behandlung

**Die Lösung:** Wir haben in beiden Projekten denselben deterministischen Testvektor (fester PSK, feste RFC-7748-Privatschlüssel, feste Nonces) mit exakt denselben erwarteten 32-Byte-Hex-Werten verankert:
- Kotlin: [`CryptoAndTunnelTest.kt`](../android-app/app/src/test/java/dev/pixelsshagent/crypto/CryptoAndTunnelTest.kt) (`PSA1 deterministic cross-language key derivation vector`)
- Rust: [`crypto.rs`](../debian-bridge/src/crypto.rs) (`psa1_cross_language_key_derivation_matches_kotlin`)

Da beide Tests auf exakt dieselben 5 Hashes (`authKey`, `c2sKey`, `s2cKey`, `serverMac`, `clientMac`) kamen, lief der erste echte Live-Handshake zwischen Rust unter Windows und der Android-App im Emulator **auf Anhieb beim allerersten Versuch** durch.
