package io.github.moses70.pixelsshagent.ssh

import java.math.BigInteger
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.util.Base64

enum class SshKeyAlgorithm(val sshName: String, val displayName: String) {
    ECDSA_P256("ecdsa-sha2-nistp256", "ECDSA P-256 (Keystore)"),
    ED25519("ssh-ed25519", "Ed25519");

    companion object {
        fun fromSshName(name: String): SshKeyAlgorithm? = entries.firstOrNull { it.sshName == name }
    }
}

/**
 * Represents an SSH public key in OpenSSH wire format (RFC 4253 / RFC 5656 / RFC 8709).
 */
data class SshPublicKey(
    val algorithm: SshKeyAlgorithm,
    val blob: ByteArray,
) {
    /**
     * OpenSSH SHA-256 fingerprint format: "SHA256:<base64 without padding>"
     */
    fun sha256Fingerprint(): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(blob)
        val b64 = Base64.getEncoder().withoutPadding().encodeToString(digest)
        return "SHA256:$b64"
    }

    /**
     * OpenSSH authorized_keys line format: "<algorithm> <base64_blob> <comment>"
     */
    fun toAuthorizedKeysLine(comment: String = ""): String {
        val b64 = Base64.getEncoder().encodeToString(blob)
        return if (comment.isBlank()) {
            "${algorithm.sshName} $b64"
        } else {
            "${algorithm.sshName} $b64 ${comment.trim()}"
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SshPublicKey) return false
        return algorithm == other.algorithm && blob.contentEquals(other.blob)
    }

    override fun hashCode(): Int = 31 * algorithm.hashCode() + blob.contentHashCode()

    companion object {
        private const val NIST_P256_CURVE_NAME = "nistp256"
        private const val P256_COORD_SIZE = 32
        private const val ED25519_PUBKEY_SIZE = 32

        /**
         * Builds an RFC 5656 ecdsa-sha2-nistp256 public key blob from raw (x, y) coordinates.
         */
        fun fromEcdsaP256(x: BigInteger, y: BigInteger): SshPublicKey {
            val uncompressed = ByteArray(1 + P256_COORD_SIZE * 2)
            uncompressed[0] = 0x04
            writeFixedUnsigned(x, uncompressed, 1, P256_COORD_SIZE)
            writeFixedUnsigned(y, uncompressed, 1 + P256_COORD_SIZE, P256_COORD_SIZE)

            val blob = SshWireWriter()
                .writeString(SshKeyAlgorithm.ECDSA_P256.sshName)
                .writeString(NIST_P256_CURVE_NAME)
                .writeBytes(uncompressed)
                .toByteArray()

            return SshPublicKey(SshKeyAlgorithm.ECDSA_P256, blob)
        }

        fun fromEcdsaP256(key: ECPublicKey): SshPublicKey {
            val point = key.w
            return fromEcdsaP256(point.affineX, point.affineY)
        }

        /**
         * Builds an RFC 8709 ssh-ed25519 public key blob from a 32-byte raw public key.
         */
        fun fromEd25519(rawPublicKey: ByteArray): SshPublicKey {
            require(rawPublicKey.size == ED25519_PUBKEY_SIZE) {
                "Ed25519 public key must be 32 bytes, got ${rawPublicKey.size}"
            }
            val blob = SshWireWriter()
                .writeString(SshKeyAlgorithm.ED25519.sshName)
                .writeBytes(rawPublicKey)
                .toByteArray()
            return SshPublicKey(SshKeyAlgorithm.ED25519, blob)
        }

        /**
         * Parses and validates an OpenSSH public key blob.
         */
        fun fromBlob(blob: ByteArray): SshPublicKey {
            val reader = SshWireReader(blob)
            val algoName = reader.readString()
            val algo = SshKeyAlgorithm.fromSshName(algoName)
                ?: throw SshWireException("Unsupported SSH key algorithm: $algoName")
            when (algo) {
                SshKeyAlgorithm.ECDSA_P256 -> {
                    val curve = reader.readString()
                    if (curve != NIST_P256_CURVE_NAME) {
                        throw SshWireException("Unsupported ECDSA curve: $curve")
                    }
                    val q = reader.readBytes()
                    if (q.size != 65 || q[0] != 0x04.toByte()) {
                        throw SshWireException("Invalid uncompressed P-256 point length/prefix")
                    }
                }
                SshKeyAlgorithm.ED25519 -> {
                    val raw = reader.readBytes()
                    if (raw.size != ED25519_PUBKEY_SIZE) {
                        throw SshWireException("Invalid Ed25519 public key length: ${raw.size}")
                    }
                }
            }
            reader.ensureConsumed()
            return SshPublicKey(algo, blob.copyOf())
        }

        internal fun writeFixedUnsigned(value: BigInteger, dest: ByteArray, offset: Int, length: Int) {
            require(value.signum() >= 0) { "Coordinate must be non-negative" }
            val raw = value.toByteArray()
            val srcStart = if (raw.size > length && raw[0] == 0.toByte()) raw.size - length else 0
            val copyLen = raw.size - srcStart
            require(copyLen <= length) { "Integer exceeds $length bytes" }
            val destStart = offset + (length - copyLen)
            System.arraycopy(raw, srcStart, dest, destStart, copyLen)
        }
    }
}
