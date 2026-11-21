package io.github.moses70.pixelsshagent.ssh

import java.math.BigInteger

/**
 * Formats cryptographic signatures into OpenSSH wire signature blobs.
 */
object SshSignature {

    /**
     * Converts a JCA ASN.1 DER-encoded ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`)
     * into an RFC 5656 OpenSSH `ecdsa-sha2-nistp256` signature blob:
     *   string "ecdsa-sha2-nistp256"
     *   string (mpint r || mpint s)
     */
    fun encodeEcdsaP256FromDer(derSignature: ByteArray): ByteArray {
        val (r, s) = parseDerEcdsaSignature(derSignature)
        val inner = SshWireWriter()
            .writeMpint(r)
            .writeMpint(s)
            .toByteArray()
        return SshWireWriter()
            .writeString(SshKeyAlgorithm.ECDSA_P256.sshName)
            .writeBytes(inner)
            .toByteArray()
    }

    /**
     * Formats a raw 64-byte Ed25519 signature into an RFC 8709 OpenSSH `ssh-ed25519` signature blob:
     *   string "ssh-ed25519"
     *   string sig64
     */
    fun encodeEd25519(rawSignature: ByteArray): ByteArray {
        require(rawSignature.size == 64) {
            "Ed25519 signature must be 64 bytes, got ${rawSignature.size}"
        }
        return SshWireWriter()
            .writeString(SshKeyAlgorithm.ED25519.sshName)
            .writeBytes(rawSignature)
            .toByteArray()
    }

    internal fun parseDerEcdsaSignature(der: ByteArray): Pair<BigInteger, BigInteger> {
        var idx = 0
        if (der.size < 8 || der[idx++] != 0x30.toByte()) {
            throw SshWireException("Invalid DER ECDSA signature: expected SEQUENCE tag 0x30")
        }
        val (seqLen, nextIdx) = readDerLength(der, idx)
        idx = nextIdx
        if (idx + seqLen != der.size) {
            throw SshWireException("Invalid DER ECDSA signature: sequence length mismatch")
        }

        val (r, afterR) = readDerInteger(der, idx)
        val (s, afterS) = readDerInteger(der, afterR)
        if (afterS != der.size) {
            throw SshWireException("Invalid DER ECDSA signature: trailing bytes")
        }
        if (r.signum() <= 0 || s.signum() <= 0) {
            throw SshWireException("Invalid DER ECDSA signature: r and s must be positive")
        }
        return r to s
    }

    private fun readDerLength(data: ByteArray, offset: Int): Pair<Int, Int> {
        if (offset >= data.size) throw SshWireException("Truncated DER length")
        val first = data[offset].toInt() and 0xFF
        if ((first and 0x80) == 0) {
            return first to (offset + 1)
        }
        val count = first and 0x7F
        if (count == 0 || count > 2 || offset + 1 + count > data.size) {
            throw SshWireException("Invalid DER length encoding")
        }
        var len = 0
        for (i in 0 until count) {
            len = (len shl 8) or (data[offset + 1 + i].toInt() and 0xFF)
        }
        return len to (offset + 1 + count)
    }

    private fun readDerInteger(data: ByteArray, offset: Int): Pair<BigInteger, Int> {
        if (offset >= data.size || data[offset] != 0x02.toByte()) {
            throw SshWireException("Invalid DER ECDSA signature: expected INTEGER tag 0x02")
        }
        val (len, bodyStart) = readDerLength(data, offset + 1)
        if (len <= 0 || bodyStart + len > data.size) {
            throw SshWireException("Invalid DER INTEGER length: $len")
        }
        val bytes = data.copyOfRange(bodyStart, bodyStart + len)
        return BigInteger(1, bytes) to (bodyStart + len)
    }
}
