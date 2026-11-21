package io.github.moses70.pixelsshagent.ssh

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets

/**
 * Pure Kotlin implementation of RFC 4251 Section 5 SSH binary wire data types:
 * byte, uint32, string (length-prefixed byte array), utf8 string, and mpint.
 */
class SshWireWriter {
    private val out = ByteArrayOutputStream()

    fun writeByte(value: Int): SshWireWriter {
        out.write(value and 0xFF)
        return this
    }

    fun writeUint32(value: Int): SshWireWriter {
        out.write((value ushr 24) and 0xFF)
        out.write((value ushr 16) and 0xFF)
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
        return this
    }

    fun writeBytes(bytes: ByteArray): SshWireWriter {
        writeUint32(bytes.size)
        out.write(bytes)
        return this
    }

    fun writeString(text: String): SshWireWriter {
        return writeBytes(text.toByteArray(StandardCharsets.UTF_8))
    }

    /**
     * Writes a non-negative integer as RFC 4251 mpint:
     * - Zero is encoded as 0 bytes (uint32(0)).
     * - Positive integers have no leading 0x00 bytes unless the MSB of the first byte is set (0x80),
     *   in which case a single 0x00 byte is prepended.
     */
    fun writeMpint(value: BigInteger): SshWireWriter {
        require(value.signum() >= 0) { "Negative mpint not supported for SSH keys/signatures" }
        if (value.signum() == 0) {
            writeUint32(0)
            return this
        }
        // BigInteger.toByteArray() already uses two's complement minimal big-endian representation,
        // which naturally prepends 0x00 when bit 7 of the first byte is set and omits redundant zeros.
        val bytes = value.toByteArray()
        return writeBytes(bytes)
    }

    fun writeRaw(bytes: ByteArray): SshWireWriter {
        out.write(bytes)
        return this
    }

    fun toByteArray(): ByteArray = out.toByteArray()
}

class SshWireReader(private val data: ByteArray) {
    private var pos = 0

    val remaining: Int
        get() = data.size - pos

    fun readByte(): Int {
        if (remaining < 1) throw SshWireException("Unexpected EOF reading byte")
        return data[pos++].toInt() and 0xFF
    }

    fun readUint32(): Int {
        if (remaining < 4) throw SshWireException("Unexpected EOF reading uint32")
        val value = ((data[pos].toInt() and 0xFF) shl 24) or
            ((data[pos + 1].toInt() and 0xFF) shl 16) or
            ((data[pos + 2].toInt() and 0xFF) shl 8) or
            (data[pos + 3].toInt() and 0xFF)
        pos += 4
        return value
    }

    fun readBytes(maxLen: Int = MAX_STRING_LEN): ByteArray {
        val len = readUint32()
        if (len < 0 || len > maxLen || len > remaining) {
            throw SshWireException("Invalid byte string length: $len (remaining=$remaining)")
        }
        val slice = data.copyOfRange(pos, pos + len)
        pos += len
        return slice
    }

    fun readString(maxLen: Int = MAX_STRING_LEN): String {
        return String(readBytes(maxLen), StandardCharsets.UTF_8)
    }

    fun readMpint(): BigInteger {
        val bytes = readBytes()
        if (bytes.isEmpty()) return BigInteger.ZERO
        return BigInteger(bytes)
    }

    fun ensureConsumed() {
        if (remaining != 0) {
            throw SshWireException("Trailing bytes remaining: $remaining")
        }
    }

    companion object {
        const val MAX_STRING_LEN = 256 * 1024
    }
}

class SshWireException(message: String) : IllegalArgumentException(message)
