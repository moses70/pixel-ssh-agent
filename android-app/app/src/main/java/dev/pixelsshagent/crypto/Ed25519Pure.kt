package dev.pixelsshagent.crypto

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Pure Kotlin RFC 8032 Ed25519 signing and verification implementation.
 * Ensures consistent Ed25519 SSH key support on Android API 28+ without relying on API 33+ JCA providers.
 */
object Ed25519Pure {
    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val L: BigInteger = BigInteger.ONE.shiftLeft(252)
        .add(BigInteger("27742317777372353535851937790883648493"))
    private val D: BigInteger = BigInteger.valueOf(-121665)
        .multiply(BigInteger.valueOf(121666).modInverse(P))
        .mod(P)
    private val TWO_D: BigInteger = D.shiftLeft(1).mod(P)
    private val SQRT_M1: BigInteger = BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).shiftRight(2), P)

    private val BX = BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202")
    private val BY = BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960")
    private val BASE = ExtPoint(BX, BY, BigInteger.ONE, BX.multiply(BY).mod(P))
    private val IDENTITY = ExtPoint(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)

    private data class ExtPoint(
        val x: BigInteger,
        val y: BigInteger,
        val z: BigInteger,
        val t: BigInteger,
    )

    fun generateSeed(random: SecureRandom = SecureRandom()): ByteArray {
        return ByteArray(32).also { random.nextBytes(it) }
    }

    fun publicKeyFromSeed(seed: ByteArray): ByteArray {
        require(seed.size == 32) { "Ed25519 seed must be 32 bytes" }
        val h = sha512(seed)
        val a = clampScalar(h.copyOfRange(0, 32))
        return encodePoint(scalarMult(BASE, a))
    }

    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        require(seed.size == 32) { "Ed25519 seed must be 32 bytes" }
        val h = sha512(seed)
        val a = clampScalar(h.copyOfRange(0, 32))
        val prefix = h.copyOfRange(32, 64)
        val pubKey = encodePoint(scalarMult(BASE, a))

        val rHash = sha512(prefix, message)
        val r = decodeLittleEndian(rHash).mod(L)
        val rPoint = encodePoint(scalarMult(BASE, r))

        val kHash = sha512(rPoint, pubKey, message)
        val k = decodeLittleEndian(kHash).mod(L)
        val s = r.add(k.multiply(a)).mod(L)

        val sig = ByteArray(64)
        System.arraycopy(rPoint, 0, sig, 0, 32)
        System.arraycopy(encodeLittleEndian32(s), 0, sig, 32, 32)
        return sig
    }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != 32 || signature.size != 64) return false
        val aPoint = decodePoint(publicKey) ?: return false
        val rBytes = signature.copyOfRange(0, 32)
        val rPoint = decodePoint(rBytes) ?: return false
        val s = decodeLittleEndian(signature.copyOfRange(32, 64))
        if (s >= L) return false

        val kHash = sha512(rBytes, publicKey, message)
        val k = decodeLittleEndian(kHash).mod(L)

        val lhs = scalarMult(BASE, s)
        val rhs = pointAdd(rPoint, scalarMult(aPoint, k))
        return pointsEqual(lhs, rhs)
    }

    private fun clampScalar(bytes: ByteArray): BigInteger {
        val c = bytes.copyOf()
        c[0] = (c[0].toInt() and 248).toByte()
        c[31] = (c[31].toInt() and 63).toByte()
        c[31] = (c[31].toInt() or 64).toByte()
        return decodeLittleEndian(c)
    }

    private fun pointAdd(p1: ExtPoint, p2: ExtPoint): ExtPoint {
        val a = p1.y.subtract(p1.x).multiply(p2.y.subtract(p2.x)).mod(P)
        val b = p1.y.add(p1.x).multiply(p2.y.add(p2.x)).mod(P)
        val c = p1.t.multiply(TWO_D).mod(P).multiply(p2.t).mod(P)
        val d = p1.z.multiply(BigInteger.TWO).multiply(p2.z).mod(P)
        val e = b.subtract(a).mod(P)
        val f = d.subtract(c).mod(P)
        val g = d.add(c).mod(P)
        val h = b.add(a).mod(P)

        val x3 = e.multiply(f).mod(P)
        val y3 = g.multiply(h).mod(P)
        val t3 = e.multiply(h).mod(P)
        val z3 = f.multiply(g).mod(P)
        return ExtPoint(x3, y3, z3, t3)
    }

    private fun scalarMult(base: ExtPoint, scalar: BigInteger): ExtPoint {
        var acc = IDENTITY
        var addend = base
        var k = scalar
        while (k.signum() > 0) {
            if (k.testBit(0)) {
                acc = pointAdd(acc, addend)
            }
            addend = pointAdd(addend, addend)
            k = k.shiftRight(1)
        }
        return acc
    }

    private fun encodePoint(pt: ExtPoint): ByteArray {
        val zInv = pt.z.modInverse(P)
        val x = pt.x.multiply(zInv).mod(P)
        val y = pt.y.multiply(zInv).mod(P)
        val out = encodeLittleEndian32(y)
        if (x.testBit(0)) {
            out[31] = (out[31].toInt() or 0x80).toByte()
        }
        return out
    }

    private fun decodePoint(encoded: ByteArray): ExtPoint? {
        if (encoded.size != 32) return null
        val signBit = (encoded[31].toInt() and 0x80) != 0
        val yBytes = encoded.copyOf()
        yBytes[31] = (yBytes[31].toInt() and 0x7F).toByte()
        val y = decodeLittleEndian(yBytes)
        if (y >= P) return null

        val y2 = y.multiply(y).mod(P)
        val u = y2.subtract(BigInteger.ONE).mod(P)
        val v = D.multiply(y2).add(BigInteger.ONE).mod(P)
        val v3 = v.multiply(v).mod(P).multiply(v).mod(P)
        val v7 = v3.multiply(v3).mod(P).multiply(v).mod(P)

        val exp = P.subtract(BigInteger.valueOf(5)).shiftRight(3)
        var x = u.multiply(v3).mod(P).multiply(u.multiply(v7).mod(P).modPow(exp, P)).mod(P)

        val vx2 = v.multiply(x).mod(P).multiply(x).mod(P)
        if (vx2 != u) {
            if (vx2 == P.subtract(u).mod(P)) {
                x = x.multiply(SQRT_M1).mod(P)
            } else {
                return null
            }
        }
        if (x.signum() == 0 && signBit) return null
        if (x.testBit(0) != signBit) {
            x = P.subtract(x).mod(P)
        }
        return ExtPoint(x, y, BigInteger.ONE, x.multiply(y).mod(P))
    }

    private fun pointsEqual(p1: ExtPoint, p2: ExtPoint): Boolean {
        val xEq = p1.x.multiply(p2.z).subtract(p2.x.multiply(p1.z)).mod(P).signum() == 0
        val yEq = p1.y.multiply(p2.z).subtract(p2.y.multiply(p1.z)).mod(P).signum() == 0
        return xEq && yEq
    }

    private fun sha512(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-512")
        for (p in parts) md.update(p)
        return md.digest()
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
