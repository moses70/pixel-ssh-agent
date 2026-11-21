package dev.pixelsshagent.crypto

import java.math.BigInteger
import java.security.SecureRandom

/**
 * Pure Kotlin RFC 7748 X25519 Diffie-Hellman implementation.
 * Works identically across JVM 17 tests and Android API 28+.
 */
object X25519Pure {
    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val P_MINUS_2: BigInteger = P.subtract(BigInteger.TWO)
    private val A24: BigInteger = BigInteger.valueOf(121665)
    private val BASEPOINT: ByteArray = ByteArray(32).apply { this[0] = 9 }

    fun generatePrivateKey(random: SecureRandom = SecureRandom()): ByteArray {
        return ByteArray(32).also { random.nextBytes(it) }
    }

    fun publicKeyFromPrivate(privateKey: ByteArray): ByteArray {
        return scalarMult(privateKey, BASEPOINT)
    }

    fun scalarMult(scalarBytes: ByteArray, uBytes: ByteArray): ByteArray {
        require(scalarBytes.size == 32) { "X25519 scalar must be 32 bytes" }
        require(uBytes.size == 32) { "X25519 u-coordinate must be 32 bytes" }

        val clamped = scalarBytes.copyOf()
        clamped[0] = (clamped[0].toInt() and 248).toByte()
        clamped[31] = (clamped[31].toInt() and 127).toByte()
        clamped[31] = (clamped[31].toInt() or 64).toByte()
        val k = decodeLittleEndian(clamped)

        val uMasked = uBytes.copyOf()
        uMasked[31] = (uMasked[31].toInt() and 127).toByte()
        val x1 = decodeLittleEndian(uMasked).mod(P)

        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE
        var swap = 0

        for (t in 254 downTo 0) {
            val kt = if (k.testBit(t)) 1 else 0
            swap = swap xor kt
            if (swap != 0) {
                val tx = x2; x2 = x3; x3 = tx
                val tz = z2; z2 = z3; z3 = tz
            }
            swap = kt

            val a = x2.add(z2).mod(P)
            val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2).mod(P)
            val bb = b.multiply(b).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)

            val daPlusCb = da.add(cb).mod(P)
            val daMinusCb = da.subtract(cb).mod(P)

            x3 = daPlusCb.multiply(daPlusCb).mod(P)
            z3 = x1.multiply(daMinusCb.multiply(daMinusCb).mod(P)).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e.multiply(aa.add(A24.multiply(e).mod(P)).mod(P)).mod(P)
        }

        if (swap != 0) {
            val tx = x2; x2 = x3; x3 = tx
            val tz = z2; z2 = z3; z3 = tz
        }

        val result = x2.multiply(z2.modPow(P_MINUS_2, P)).mod(P)
        return encodeLittleEndian32(result)
    }

    fun isAllZero(bytes: ByteArray): Boolean {
        var acc = 0
        for (b in bytes) {
            acc = acc or (b.toInt() and 0xFF)
        }
        return acc == 0
    }

    private fun decodeLittleEndian(bytes: ByteArray): BigInteger {
        val be = ByteArray(bytes.size)
        for (i in bytes.indices) {
            be[bytes.size - 1 - i] = bytes[i]
        }
        return BigInteger(1, be)
    }

    private fun encodeLittleEndian32(value: BigInteger): ByteArray {
        val out = ByteArray(32)
        val be = value.toByteArray()
        var outIdx = 0
        for (i in be.size - 1 downTo 0) {
            if (outIdx >= 32) break
            out[outIdx++] = be[i]
        }
        return out
    }
}
