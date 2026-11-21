use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

pub const MAGIC: &[u8; 4] = b"PSA1";
pub const VERSION: u16 = 1;
pub const CLIENT_HELLO_LEN: usize = 72;
pub const SERVER_HELLO_LEN: usize = 104;
pub const CLIENT_FINISH_LEN: usize = 32;
pub const MAX_CIPHERTEXT_LEN: usize = 1_048_576;
pub const GCM_TAG_LEN: usize = 16;

const INFO_AUTH: &[u8] = b"PSA1-auth";
const INFO_C2S: &[u8] = b"PSA1-c2s-key";
const INFO_S2C: &[u8] = b"PSA1-s2c-key";
const LABEL_SERVER_AUTH: &[u8] = b"PSA1-server-auth";
const LABEL_CLIENT_AUTH: &[u8] = b"PSA1-client-auth";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub auth_key: [u8; 32],
    pub c2s_key: [u8; 32],
    pub s2c_key: [u8; 32],
}

pub fn build_hello_header(eph_pub: &[u8; 32], nonce: &[u8; 32]) -> [u8; CLIENT_HELLO_LEN] {
    let mut out = [0u8; CLIENT_HELLO_LEN];
    out[0..4].copy_from_slice(MAGIC);
    out[4..6].copy_from_slice(&VERSION.to_be_bytes());
    out[6..8].copy_from_slice(&0u16.to_be_bytes());
    out[8..40].copy_from_slice(eph_pub);
    out[40..72].copy_from_slice(nonce);
    out
}

pub fn derive_session_keys(
    psk: &[u8; 32],
    shared_secret: &[u8; 32],
    client_hello: &[u8; CLIENT_HELLO_LEN],
    server_hello_header: &[u8; CLIENT_HELLO_LEN],
) -> io::Result<SessionKeys> {
    if shared_secret.iter().all(|&b| b == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid all-zero X25519 shared secret",
        ));
    }

    let mut transcript = [0u8; CLIENT_HELLO_LEN * 2];
    transcript[0..CLIENT_HELLO_LEN].copy_from_slice(client_hello);
    transcript[CLIENT_HELLO_LEN..].copy_from_slice(server_hello_header);

    let salt = Sha256::digest(transcript);
    let mut ikm = [0u8; 64];
    ikm[0..32].copy_from_slice(psk);
    ikm[32..64].copy_from_slice(shared_secret);

    let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);

    let mut auth_key = [0u8; 32];
    let mut c2s_key = [0u8; 32];
    let mut s2c_key = [0u8; 32];
    hk.expand(INFO_AUTH, &mut auth_key)
        .map_err(|_| io::Error::other("HKDF expand auth failed"))?;
    hk.expand(INFO_C2S, &mut c2s_key)
        .map_err(|_| io::Error::other("HKDF expand c2s failed"))?;
    hk.expand(INFO_S2C, &mut s2c_key)
        .map_err(|_| io::Error::other("HKDF expand s2c failed"))?;

    Ok(SessionKeys {
        auth_key,
        c2s_key,
        s2c_key,
    })
}

pub fn compute_mac(
    auth_key: &[u8; 32],
    label: &[u8],
    client_hello: &[u8; CLIENT_HELLO_LEN],
    server_hello_header: &[u8; CLIENT_HELLO_LEN],
) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(auth_key).expect("HMAC accepts 32-byte key");
    mac.update(label);
    mac.update(client_hello);
    mac.update(server_hello_header);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

pub fn compute_server_mac(
    auth_key: &[u8; 32],
    client_hello: &[u8; CLIENT_HELLO_LEN],
    server_hello_header: &[u8; CLIENT_HELLO_LEN],
) -> [u8; 32] {
    compute_mac(
        auth_key,
        LABEL_SERVER_AUTH,
        client_hello,
        server_hello_header,
    )
}

pub fn compute_client_mac(
    auth_key: &[u8; 32],
    client_hello: &[u8; CLIENT_HELLO_LEN],
    server_hello_header: &[u8; CLIENT_HELLO_LEN],
) -> [u8; 32] {
    compute_mac(
        auth_key,
        LABEL_CLIENT_AUTH,
        client_hello,
        server_hello_header,
    )
}

fn validate_header(header: &[u8; CLIENT_HELLO_LEN]) -> io::Result<()> {
    if &header[0..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid PSA1 magic",
        ));
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported PSA1 version: {version}"),
        ));
    }
    Ok(())
}

/// Performs the Debian server-side PSA1 handshake with the connecting Android app.
/// Returns `(send_key = s2c_key, recv_key = c2s_key)`.
pub fn handshake_server<S: Read + Write>(
    stream: &mut S,
    psk: &[u8; 32],
) -> io::Result<([u8; 32], [u8; 32])> {
    let mut client_hello = [0u8; CLIENT_HELLO_LEN];
    stream.read_exact(&mut client_hello)?;
    validate_header(&client_hello)?;

    let mut client_pub_bytes = [0u8; 32];
    client_pub_bytes.copy_from_slice(&client_hello[8..40]);

    let server_priv = StaticSecret::random_from_rng(OsRng);
    let server_pub = PublicKey::from(&server_priv);
    let mut server_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut server_nonce);

    let server_hello_header = build_hello_header(server_pub.as_bytes(), &server_nonce);
    let shared = server_priv.diffie_hellman(&PublicKey::from(client_pub_bytes));
    if !shared.was_contributory() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Client sent low-order X25519 key",
        ));
    }

    let keys = derive_session_keys(psk, shared.as_bytes(), &client_hello, &server_hello_header)?;
    let server_mac = compute_server_mac(&keys.auth_key, &client_hello, &server_hello_header);

    let mut server_hello = [0u8; SERVER_HELLO_LEN];
    server_hello[0..CLIENT_HELLO_LEN].copy_from_slice(&server_hello_header);
    server_hello[CLIENT_HELLO_LEN..SERVER_HELLO_LEN].copy_from_slice(&server_mac);
    stream.write_all(&server_hello)?;
    stream.flush()?;

    let mut client_mac = [0u8; CLIENT_FINISH_LEN];
    stream.read_exact(&mut client_mac)?;
    let expected_client_mac =
        compute_client_mac(&keys.auth_key, &client_hello, &server_hello_header);

    if !bool::from(expected_client_mac.ct_eq(&client_mac)) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Client authentication failed (PSK mismatch)",
        ));
    }

    Ok((keys.s2c_key, keys.c2s_key))
}

fn build_nonce(seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&seq.to_be_bytes());
    nonce
}

fn build_aad(ciphertext_len: u32, seq: u64) -> [u8; 12] {
    let mut aad = [0u8; 12];
    aad[0..4].copy_from_slice(&ciphertext_len.to_be_bytes());
    aad[4..12].copy_from_slice(&seq.to_be_bytes());
    aad
}

pub struct Psa1Writer<W: Write> {
    inner: W,
    cipher: Aes256Gcm,
    seq: u64,
}

impl<W: Write> Psa1Writer<W> {
    pub fn new(inner: W, key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 accepts 32-byte key");
        Self {
            inner,
            cipher,
            seq: 0,
        }
    }

    pub fn write_record(&mut self, plaintext: &[u8]) -> io::Result<()> {
        if self.seq == u64::MAX {
            return Err(io::Error::other("Send sequence counter exhausted"));
        }
        let ciphertext_len = plaintext
            .len()
            .checked_add(GCM_TAG_LEN)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Record overflow"))?;
        if ciphertext_len > MAX_CIPHERTEXT_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Plaintext exceeds max PSA1 record size",
            ));
        }

        let seq = self.seq;
        self.seq += 1;
        let nonce_bytes = build_nonce(seq);
        let aad = build_aad(ciphertext_len as u32, seq);

        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| io::Error::other("AES-GCM encrypt failed"))?;

        self.inner
            .write_all(&(ciphertext.len() as u32).to_be_bytes())?;
        self.inner.write_all(&ciphertext)?;
        self.inner.flush()
    }
}

pub struct Psa1Reader<R: Read> {
    inner: R,
    cipher: Aes256Gcm,
    seq: u64,
}

impl<R: Read> Psa1Reader<R> {
    pub fn new(inner: R, key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 accepts 32-byte key");
        Self {
            inner,
            cipher,
            seq: 0,
        }
    }

    pub fn read_record(&mut self) -> io::Result<Vec<u8>> {
        if self.seq == u64::MAX {
            return Err(io::Error::other("Receive sequence counter exhausted"));
        }
        let mut len_buf = [0u8; 4];
        self.inner.read_exact(&mut len_buf)?;
        let ciphertext_len = u32::from_be_bytes(len_buf) as usize;
        if !(GCM_TAG_LEN..=MAX_CIPHERTEXT_LEN).contains(&ciphertext_len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid PSA1 record length: {ciphertext_len}"),
            ));
        }

        let mut ciphertext = vec![0u8; ciphertext_len];
        self.inner.read_exact(&mut ciphertext)?;

        let seq = self.seq;
        self.seq += 1;
        let nonce_bytes = build_nonce(seq);
        let aad = build_aad(ciphertext_len as u32, seq);

        self.cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "AES-GCM authentication failed")
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Exact cross-language test vector verified identically in Kotlin's CryptoAndTunnelTest.
    #[test]
    fn psa1_cross_language_key_derivation_matches_kotlin() {
        let mut psk = [0u8; 32];
        for (i, b) in psk.iter_mut().enumerate() {
            *b = i as u8;
        }
        let client_priv_bytes: [u8; 32] =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let server_priv_bytes: [u8; 32] =
            hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .unwrap()
                .try_into()
                .unwrap();

        let mut client_nonce = [0u8; 32];
        let mut server_nonce = [0u8; 32];
        for i in 0..32 {
            client_nonce[i] = (0xA0 + i) as u8;
            server_nonce[i] = (0x50 + i) as u8;
        }

        let client_priv = StaticSecret::from(client_priv_bytes);
        let server_priv = StaticSecret::from(server_priv_bytes);
        let client_pub = PublicKey::from(&client_priv);
        let server_pub = PublicKey::from(&server_priv);
        let shared = client_priv.diffie_hellman(&server_pub);

        let client_hello = build_hello_header(client_pub.as_bytes(), &client_nonce);
        let server_hello_header = build_hello_header(server_pub.as_bytes(), &server_nonce);

        let keys =
            derive_session_keys(&psk, shared.as_bytes(), &client_hello, &server_hello_header)
                .unwrap();
        let server_mac = compute_server_mac(&keys.auth_key, &client_hello, &server_hello_header);
        let client_mac = compute_client_mac(&keys.auth_key, &client_hello, &server_hello_header);

        assert_eq!(
            hex::encode(keys.auth_key),
            "a260ea74e49efffaed1e48ac69daf2a3cd57b9f6f9f83a570ba8bf731c7aa35a"
        );
        assert_eq!(
            hex::encode(keys.c2s_key),
            "27b7e7b75f24265f9ec5c3a5557901b68e20c96d2c16586b2a14ba3480ec91d8"
        );
        assert_eq!(
            hex::encode(keys.s2c_key),
            "9ca4b9542b91da2ed3cc83f99556f8e5df7f69751ffc91e4c93fecfb611837a9"
        );
        assert_eq!(
            hex::encode(server_mac),
            "810d376f80e164aa535f46e0eb558d9263a46e140252aa1f207bded223e1ba8c"
        );
        assert_eq!(
            hex::encode(client_mac),
            "419d07be7caaaa9a1a36098874504a09ae6c2ba14371b41d8a468647e6f16f83"
        );
    }

    #[test]
    fn encrypted_record_roundtrip_and_tamper_detection() {
        let key = [0x5Au8; 32];
        let mut wire = Vec::new();
        {
            let mut writer = Psa1Writer::new(&mut wire, &key);
            writer.write_record(b"first ssh agent frame").unwrap();
            writer.write_record(b"second ssh agent frame").unwrap();
        }

        let mut reader = Psa1Reader::new(Cursor::new(&wire), &key);
        assert_eq!(reader.read_record().unwrap(), b"first ssh agent frame");
        assert_eq!(reader.read_record().unwrap(), b"second ssh agent frame");

        // Flip 1 bit in ciphertext and verify AES-GCM rejects it
        let mut tampered = wire.clone();
        tampered[10] ^= 0x01;
        let mut bad_reader = Psa1Reader::new(Cursor::new(&tampered), &key);
        assert!(bad_reader.read_record().is_err());
    }
}
