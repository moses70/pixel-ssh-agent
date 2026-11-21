package io.github.moses70.pixelsshagent.crypto

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * RFC 5869 HKDF-SHA256 implementation.
 */
object HkdfSha256 {
    fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        for (part in parts) {
            mac.update(part)
        }
        return mac.doFinal()
    }

    fun extract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
        return hmacSha256(effectiveSalt, ikm)
    }

    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(255 * 32)) { "Invalid HKDF length: $length" }
        val result = ByteArray(length)
        var offset = 0
        var prev = ByteArray(0)
        var counter = 1
        while (offset < length) {
            prev = hmacSha256(prk, prev, info, byteArrayOf(counter.toByte()))
            val take = minOf(prev.size, length - offset)
            System.arraycopy(prev, 0, result, offset, take)
            offset += take
            counter++
        }
        return result
    }
}

/**
 * Exact implementation of the PSA1 authenticated encrypted tunnel protocol (docs/PROTOCOL.md).
 */
object Psa1Protocol {
    val MAGIC: ByteArray = "PSA1".toByteArray(StandardCharsets.US_ASCII)
    const val VERSION: Int = 1
    const val CLIENT_HELLO_LEN: Int = 72
    const val SERVER_HELLO_LEN: Int = 104
    const val CLIENT_FINISH_LEN: Int = 32
    const val MAX_CIPHERTEXT_LEN: Int = 1_048_576
    const val GCM_TAG_LEN: Int = 16

    private val INFO_AUTH = "PSA1-auth".toByteArray(StandardCharsets.US_ASCII)
    private val INFO_C2S = "PSA1-c2s-key".toByteArray(StandardCharsets.US_ASCII)
    private val INFO_S2C = "PSA1-s2c-key".toByteArray(StandardCharsets.US_ASCII)
    private val LABEL_SERVER_AUTH = "PSA1-server-auth".toByteArray(StandardCharsets.US_ASCII)
    private val LABEL_CLIENT_AUTH = "PSA1-client-auth".toByteArray(StandardCharsets.US_ASCII)

    data class SessionKeys(
        val authKey: ByteArray,
        val c2sKey: ByteArray,
        val s2cKey: ByteArray,
    )

    fun buildHelloHeader(ephPub: ByteArray, nonce: ByteArray): ByteArray {
        require(ephPub.size == 32 && nonce.size == 32)
        val out = ByteArray(CLIENT_HELLO_LEN)
        System.arraycopy(MAGIC, 0, out, 0, 4)
        out[4] = ((VERSION ushr 8) and 0xFF).toByte()
        out[5] = (VERSION and 0xFF).toByte()
        out[6] = 0
        out[7] = 0
        System.arraycopy(ephPub, 0, out, 8, 32)
        System.arraycopy(nonce, 0, out, 40, 32)
        return out
    }

    fun deriveSessionKeys(
        psk: ByteArray,
        sharedSecret: ByteArray,
        clientHello: ByteArray,
        serverHelloHeader: ByteArray,
    ): SessionKeys {
        require(psk.size == 32) { "PSK must be 32 bytes" }
        require(sharedSecret.size == 32 && !X25519Pure.isAllZero(sharedSecret)) {
            "Invalid X25519 shared secret"
        }
        require(clientHello.size == CLIENT_HELLO_LEN)
        require(serverHelloHeader.size == CLIENT_HELLO_LEN)

        val transcript = ByteArray(CLIENT_HELLO_LEN * 2)
        System.arraycopy(clientHello, 0, transcript, 0, CLIENT_HELLO_LEN)
        System.arraycopy(serverHelloHeader, 0, transcript, CLIENT_HELLO_LEN, CLIENT_HELLO_LEN)

        val salt = MessageDigest.getInstance("SHA-256").digest(transcript)
        val ikm = ByteArray(64)
        System.arraycopy(psk, 0, ikm, 0, 32)
        System.arraycopy(sharedSecret, 0, ikm, 32, 32)

        val prk = HkdfSha256.extract(salt, ikm)
        return SessionKeys(
            authKey = HkdfSha256.expand(prk, INFO_AUTH, 32),
            c2sKey = HkdfSha256.expand(prk, INFO_C2S, 32),
            s2cKey = HkdfSha256.expand(prk, INFO_S2C, 32),
        )
    }

    fun computeServerMac(authKey: ByteArray, clientHello: ByteArray, serverHelloHeader: ByteArray): ByteArray {
        return HkdfSha256.hmacSha256(authKey, LABEL_SERVER_AUTH, clientHello, serverHelloHeader)
    }

    fun computeClientMac(authKey: ByteArray, clientHello: ByteArray, serverHelloHeader: ByteArray): ByteArray {
        return HkdfSha256.hmacSha256(authKey, LABEL_CLIENT_AUTH, clientHello, serverHelloHeader)
    }

    /**
     * Runs the Android client-side PSA1 handshake over raw streams and returns an encrypted [Psa1Session].
     */
    fun handshakeClient(
        input: InputStream,
        output: OutputStream,
        psk: ByteArray,
        random: SecureRandom = SecureRandom(),
    ): Psa1Session {
        require(psk.size == 32) { "PSK must be 32 bytes" }
        val clientPriv = X25519Pure.generatePrivateKey(random)
        val clientPub = X25519Pure.publicKeyFromPrivate(clientPriv)
        val clientNonce = ByteArray(32).also { random.nextBytes(it) }
        val clientHello = buildHelloHeader(clientPub, clientNonce)

        output.write(clientHello)
        output.flush()

        val serverHello = ByteArray(SERVER_HELLO_LEN)
        DataInputStream(input).readFully(serverHello)

        validateHeader(serverHello)
        val serverHelloHeader = serverHello.copyOfRange(0, CLIENT_HELLO_LEN)
        val serverPub = serverHello.copyOfRange(8, 40)
        val serverMac = serverHello.copyOfRange(72, 104)

        val sharedSecret = X25519Pure.scalarMult(clientPriv, serverPub)
        if (X25519Pure.isAllZero(sharedSecret)) {
            throw Psa1SecurityException("Peer sent low-order X25519 public key")
        }

        val keys = deriveSessionKeys(psk, sharedSecret, clientHello, serverHelloHeader)
        val expectedServerMac = computeServerMac(keys.authKey, clientHello, serverHelloHeader)
        if (!MessageDigest.isEqual(expectedServerMac, serverMac)) {
            throw Psa1SecurityException("Server authentication failed (invalid PSK or peer)")
        }

        val clientMac = computeClientMac(keys.authKey, clientHello, serverHelloHeader)
        output.write(clientMac)
        output.flush()

        return Psa1Session(
            input = DataInputStream(input),
            output = DataOutputStream(output),
            sendKey = keys.c2sKey,
            recvKey = keys.s2cKey,
        )
    }

    /**
     * Server-side handshake helper (primarily for end-to-end tests and interop verification).
     */
    fun handshakeServer(
        input: InputStream,
        output: OutputStream,
        psk: ByteArray,
        random: SecureRandom = SecureRandom(),
    ): Psa1Session {
        require(psk.size == 32) { "PSK must be 32 bytes" }
        val dis = DataInputStream(input)
        val clientHello = ByteArray(CLIENT_HELLO_LEN)
        dis.readFully(clientHello)
        validateHeader(clientHello)

        val clientPub = clientHello.copyOfRange(8, 40)
        val serverPriv = X25519Pure.generatePrivateKey(random)
        val serverPub = X25519Pure.publicKeyFromPrivate(serverPriv)
        val serverNonce = ByteArray(32).also { random.nextBytes(it) }
        val serverHelloHeader = buildHelloHeader(serverPub, serverNonce)

        val sharedSecret = X25519Pure.scalarMult(serverPriv, clientPub)
        if (X25519Pure.isAllZero(sharedSecret)) {
            throw Psa1SecurityException("Client sent low-order X25519 public key")
        }

        val keys = deriveSessionKeys(psk, sharedSecret, clientHello, serverHelloHeader)
        val serverMac = computeServerMac(keys.authKey, clientHello, serverHelloHeader)

        output.write(serverHelloHeader)
        output.write(serverMac)
        output.flush()

        val clientMac = ByteArray(CLIENT_FINISH_LEN)
        dis.readFully(clientMac)
        val expectedClientMac = computeClientMac(keys.authKey, clientHello, serverHelloHeader)
        if (!MessageDigest.isEqual(expectedClientMac, clientMac)) {
            throw Psa1SecurityException("Client authentication failed")
        }

        return Psa1Session(
            input = dis,
            output = DataOutputStream(output),
            sendKey = keys.s2cKey,
            recvKey = keys.c2sKey,
        )
    }

    private fun validateHeader(header: ByteArray) {
        if (header.size < CLIENT_HELLO_LEN) {
            throw Psa1SecurityException("Truncated PSA1 header")
        }
        for (i in 0 until 4) {
            if (header[i] != MAGIC[i]) {
                throw Psa1SecurityException("Invalid PSA1 magic")
            }
        }
        val version = ((header[4].toInt() and 0xFF) shl 8) or (header[5].toInt() and 0xFF)
        if (version != VERSION) {
            throw Psa1SecurityException("Unsupported PSA1 protocol version: $version")
        }
    }

    internal fun buildNonce(seq: Long): ByteArray {
        val buf = ByteBuffer.allocate(12)
        buf.putInt(0)
        buf.putLong(seq)
        return buf.array()
    }

    internal fun buildAad(ciphertextLen: Int, seq: Long): ByteArray {
        val buf = ByteBuffer.allocate(12)
        buf.putInt(ciphertextLen)
        buf.putLong(seq)
        return buf.array()
    }
}

class Psa1Session(
    private val input: DataInputStream,
    private val output: DataOutputStream,
    sendKey: ByteArray,
    recvKey: ByteArray,
) {
    private val sendKeySpec = SecretKeySpec(sendKey, "AES")
    private val recvKeySpec = SecretKeySpec(recvKey, "AES")
    private var sendSeq: Long = 0
    private var recvSeq: Long = 0
    private val writeLock = Any()
    private val readLock = Any()

    @Throws(IOException::class)
    fun writeRecord(plaintext: ByteArray) {
        synchronized(writeLock) {
            if (sendSeq == Long.MAX_VALUE) {
                throw Psa1SecurityException("Send sequence counter exhausted")
            }
            val ciphertextLen = plaintext.size + Psa1Protocol.GCM_TAG_LEN
            if (ciphertextLen > Psa1Protocol.MAX_CIPHERTEXT_LEN) {
                throw IOException("Plaintext exceeds max PSA1 record size")
            }

            val seq = sendSeq++
            val nonce = Psa1Protocol.buildNonce(seq)
            val aad = Psa1Protocol.buildAad(ciphertextLen, seq)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, sendKeySpec, GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(plaintext)

            output.writeInt(ciphertext.size)
            output.write(ciphertext)
            output.flush()
        }
    }

    @Throws(IOException::class)
    fun readRecord(): ByteArray {
        synchronized(readLock) {
            if (recvSeq == Long.MAX_VALUE) {
                throw Psa1SecurityException("Receive sequence counter exhausted")
            }
            val ciphertextLen = try {
                input.readInt()
            } catch (e: EOFException) {
                throw e
            }
            if (ciphertextLen < Psa1Protocol.GCM_TAG_LEN || ciphertextLen > Psa1Protocol.MAX_CIPHERTEXT_LEN) {
                throw Psa1SecurityException("Invalid PSA1 record length: $ciphertextLen")
            }
            val ciphertext = ByteArray(ciphertextLen)
            input.readFully(ciphertext)

            val seq = recvSeq++
            val nonce = Psa1Protocol.buildNonce(seq)
            val aad = Psa1Protocol.buildAad(ciphertextLen, seq)

            return try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, recvKeySpec, GCMParameterSpec(128, nonce))
                cipher.updateAAD(aad)
                cipher.doFinal(ciphertext)
            } catch (e: GeneralSecurityException) {
                throw Psa1SecurityException("AES-GCM authentication failed", e)
            }
        }
    }
}

class Psa1SecurityException(message: String, cause: Throwable? = null) : IOException(message, cause)

object HexCodec {
    private val HEX_CHARS = "0123456789abcdef".toCharArray()

    fun encode(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            out[i * 2] = HEX_CHARS[v ushr 4]
            out[i * 2 + 1] = HEX_CHARS[v and 0x0F]
        }
        return String(out)
    }

    fun decode(hex: String): ByteArray {
        val clean = hex.trim().replace(" ", "").replace(":", "").replace("-", "")
        require(clean.length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(clean.length / 2) { i ->
            val hi = Character.digit(clean[i * 2], 16)
            val lo = Character.digit(clean[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "Invalid hex character at index ${i * 2}" }
            ((hi shl 4) or lo).toByte()
        }
    }
}
