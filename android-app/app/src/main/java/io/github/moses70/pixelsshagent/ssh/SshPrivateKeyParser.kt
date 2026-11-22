package io.github.moses70.pixelsshagent.ssh

import io.github.moses70.pixelsshagent.crypto.BcryptPbkdf
import io.github.moses70.pixelsshagent.crypto.Ed25519Pure
import io.github.moses70.pixelsshagent.crypto.HexCodec
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Result of parsing an imported SSH private key.
 * Callers MUST wipe [secretMaterial] after wrapping it into encrypted storage.
 */
data class ParsedSshPrivateKey(
    val algorithm: SshKeyAlgorithm,
    val publicKey: SshPublicKey,
    val secretMaterial: ByteArray, // 32-byte Ed25519 seed OR 32-byte big-endian ECDSA P-256 scalar d
    val embeddedComment: String,
) {
    fun wipeSecret() {
        secretMaterial.fill(0)
    }
}

class SshKeyImportException(message: String, cause: Throwable? = null) : IllegalArgumentException(message, cause)

/**
 * Pure-Kotlin parser for OpenSSH private keys (`-----BEGIN OPENSSH PRIVATE KEY-----`,
 * both unencrypted and bcrypt+AES256 encrypted) and raw 64-hex Ed25519 seeds.
 */
object SshPrivateKeyParser {
    private val OPENSSH_MAGIC = "openssh-key-v1\u0000".toByteArray(StandardCharsets.US_ASCII)
    private const val OPENSSH_HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----"
    private const val OPENSSH_FOOTER = "-----END OPENSSH PRIVATE KEY-----"

    fun isEncryptedOpenSshKey(input: String): Boolean {
        return runCatching {
            val raw = decodeOpenSshArmor(input) ?: return false
            if (raw.size < OPENSSH_MAGIC.size) return false
            for (i in OPENSSH_MAGIC.indices) {
                if (raw[i] != OPENSSH_MAGIC[i]) return false
            }
            val reader = SshWireReader(raw.copyOfRange(OPENSSH_MAGIC.size, raw.size))
            val cipherName = reader.readString()
            cipherName != "none"
        }.getOrDefault(false)
    }

    fun parse(input: String, passphrase: String? = null): ParsedSshPrivateKey {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) {
            throw SshKeyImportException("Private key input is empty")
        }

        // 1. OpenSSH armored private key (`-----BEGIN OPENSSH PRIVATE KEY-----`)
        val opensshRaw = decodeOpenSshArmor(trimmed)
        if (opensshRaw != null) {
            return parseOpenSshV1(opensshRaw, passphrase)
        }

        // 2. Raw 64-character hex Ed25519 seed (32 bytes)
        val hexCandidate = trimmed.replace(" ", "").replace(":", "").replace("-", "")
        if (hexCandidate.length == 64 && hexCandidate.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            val seed = HexCodec.decode(hexCandidate)
            val rawPub = Ed25519Pure.publicKeyFromSeed(seed)
            return ParsedSshPrivateKey(
                algorithm = SshKeyAlgorithm.ED25519,
                publicKey = SshPublicKey.fromEd25519(rawPub),
                secretMaterial = seed,
                embeddedComment = "imported-ed25519",
            )
        }

        throw SshKeyImportException(
            "Unsupported private key format. Provide an OpenSSH private key " +
                "(-----BEGIN OPENSSH PRIVATE KEY-----) or a 64-hex Ed25519 seed.",
        )
    }

    private fun decodeOpenSshArmor(text: String): ByteArray? {
        val start = text.indexOf(OPENSSH_HEADER)
        val end = text.indexOf(OPENSSH_FOOTER)
        if (start < 0 || end < 0 || end <= start) return null
        val body = text.substring(start + OPENSSH_HEADER.length, end)
            .replace("\r", "")
            .replace("\n", "")
            .replace(" ", "")
            .trim()
        return try {
            Base64.getDecoder().decode(body)
        } catch (e: IllegalArgumentException) {
            throw SshKeyImportException("Invalid Base64 in OpenSSH private key", e)
        }
    }

    private fun parseOpenSshV1(raw: ByteArray, passphrase: String?): ParsedSshPrivateKey {
        if (raw.size < OPENSSH_MAGIC.size) {
            throw SshKeyImportException("Truncated OpenSSH key file")
        }
        for (i in OPENSSH_MAGIC.indices) {
            if (raw[i] != OPENSSH_MAGIC[i]) {
                throw SshKeyImportException("Invalid openssh-key-v1 magic header")
            }
        }

        val reader = SshWireReader(raw.copyOfRange(OPENSSH_MAGIC.size, raw.size))
        val cipherName = reader.readString()
        val kdfName = reader.readString()
        val kdfOptions = reader.readBytes()
        val numKeys = reader.readUint32()
        if (numKeys != 1) {
            throw SshKeyImportException("Only single-key OpenSSH files are supported (found $numKeys)")
        }
        val publicKeyBlob = reader.readBytes()
        val encryptedPrivateSection = reader.readBytes()

        val privateSection = decryptPrivateSection(
            cipherName = cipherName,
            kdfName = kdfName,
            kdfOptions = kdfOptions,
            encrypted = encryptedPrivateSection,
            passphrase = passphrase,
        )

        return try {
            parsePrivateSection(privateSection, publicKeyBlob)
        } finally {
            privateSection.fill(0)
        }
    }

    private fun decryptPrivateSection(
        cipherName: String,
        kdfName: String,
        kdfOptions: ByteArray,
        encrypted: ByteArray,
        passphrase: String?,
    ): ByteArray {
        if (cipherName == "none" && kdfName == "none") {
            return encrypted.copyOf()
        }
        if (kdfName != "bcrypt") {
            throw SshKeyImportException("Unsupported OpenSSH KDF: $kdfName")
        }
        if (passphrase.isNullOrEmpty()) {
            throw SshKeyImportException("This private key is encrypted — please enter its passphrase")
        }

        val kdfReader = SshWireReader(kdfOptions)
        val salt = kdfReader.readBytes()
        val rounds = kdfReader.readUint32()
        kdfReader.ensureConsumed()

        val passBytes = passphrase.toByteArray(StandardCharsets.UTF_8)
        return try {
            when (cipherName) {
                "aes256-ctr" -> {
                    val keyIv = BcryptPbkdf.deriveKey(passBytes, salt, rounds, 32 + 16)
                    try {
                        val key = keyIv.copyOfRange(0, 32)
                        val iv = keyIv.copyOfRange(32, 48)
                        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
                        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
                        cipher.doFinal(encrypted)
                    } finally {
                        keyIv.fill(0)
                    }
                }

                "aes256-gcm@openssh.com" -> {
                    val keyIv = BcryptPbkdf.deriveKey(passBytes, salt, rounds, 32 + 12)
                    try {
                        val key = keyIv.copyOfRange(0, 32)
                        val iv = keyIv.copyOfRange(32, 44)
                        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
                        cipher.doFinal(encrypted)
                    } catch (e: Exception) {
                        throw SshKeyImportException("Wrong passphrase or corrupted AES-GCM key", e)
                    } finally {
                        keyIv.fill(0)
                    }
                }

                else -> throw SshKeyImportException(
                    "Unsupported OpenSSH cipher: $cipherName (supported: none, aes256-ctr, aes256-gcm@openssh.com)",
                )
            }
        } finally {
            passBytes.fill(0)
        }
    }

    private fun parsePrivateSection(privateSection: ByteArray, expectedPubBlob: ByteArray): ParsedSshPrivateKey {
        val reader = SshWireReader(privateSection)
        val check1 = reader.readUint32()
        val check2 = reader.readUint32()
        if (check1 != check2) {
            throw SshKeyImportException("Wrong passphrase or corrupted private key (checkint mismatch)")
        }

        val keyType = reader.readString()
        val expectedPubKey = SshPublicKey.fromBlob(expectedPubBlob)

        val result = when (keyType) {
            SshKeyAlgorithm.ED25519.sshName -> {
                val pubBytes = reader.readBytes()
                val privAndPub = reader.readBytes()
                val comment = reader.readString()
                if (pubBytes.size != 32 || privAndPub.size != 64) {
                    throw SshKeyImportException("Invalid Ed25519 private key structure")
                }
                val seed = privAndPub.copyOfRange(0, 32)
                val derivedPub = Ed25519Pure.publicKeyFromSeed(seed)
                if (!derivedPub.contentEquals(pubBytes)) {
                    seed.fill(0)
                    throw SshKeyImportException("Ed25519 seed does not match embedded public key")
                }
                val parsedPub = SshPublicKey.fromEd25519(derivedPub)
                if (parsedPub != expectedPubKey) {
                    seed.fill(0)
                    throw SshKeyImportException("Private key does not match public key header")
                }
                ParsedSshPrivateKey(
                    algorithm = SshKeyAlgorithm.ED25519,
                    publicKey = parsedPub,
                    secretMaterial = seed,
                    embeddedComment = comment,
                )
            }

            SshKeyAlgorithm.ECDSA_P256.sshName -> {
                val curve = reader.readString()
                if (curve != "nistp256") {
                    throw SshKeyImportException("Unsupported ECDSA curve: $curve (only nistp256 is supported)")
                }
                val qPoint = reader.readBytes()
                if (qPoint.size != 65 || qPoint[0] != 0x04.toByte()) {
                    throw SshKeyImportException("Invalid uncompressed ECDSA P-256 point")
                }
                val scalarD = reader.readMpint()
                val comment = reader.readString()
                if (scalarD.signum() <= 0) {
                    throw SshKeyImportException("Invalid ECDSA P-256 private scalar")
                }

                val x = BigInteger(1, qPoint.copyOfRange(1, 33))
                val y = BigInteger(1, qPoint.copyOfRange(33, 65))
                val parsedPub = SshPublicKey.fromEcdsaP256(x, y)
                if (parsedPub != expectedPubKey) {
                    throw SshKeyImportException("ECDSA private key does not match public key header")
                }

                val scalarBytes = ByteArray(32)
                SshPublicKey.writeFixedUnsigned(scalarD, scalarBytes, 0, 32)
                ParsedSshPrivateKey(
                    algorithm = SshKeyAlgorithm.ECDSA_P256,
                    publicKey = parsedPub,
                    secretMaterial = scalarBytes,
                    embeddedComment = comment,
                )
            }

            else -> throw SshKeyImportException(
                "Unsupported SSH key type: $keyType (supported: ssh-ed25519, ecdsa-sha2-nistp256)",
            )
        }

        // Validate deterministic OpenSSH padding bytes (1, 2, 3, ...)
        var expectedPad = 1
        while (reader.remaining > 0) {
            val b = reader.readByte()
            if (b != (expectedPad and 0xFF)) {
                result.wipeSecret()
                throw SshKeyImportException("Invalid OpenSSH padding bytes (wrong passphrase or corrupted file)")
            }
            expectedPad++
        }

        return result
    }
}
