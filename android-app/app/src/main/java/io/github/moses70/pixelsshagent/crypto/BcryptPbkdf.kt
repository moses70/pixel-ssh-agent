package io.github.moses70.pixelsshagent.crypto

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/**
 * Pure-Kotlin implementation of OpenBSD `bcrypt_pbkdf` used by OpenSSH encrypted private keys.
 */
object BcryptPbkdf {
    private const val BCRYPT_WORDS = 8
    private const val BCRYPT_HASHSIZE = BCRYPT_WORDS * 4 // 32 bytes
    private val MAGIC_BYTES = "OxychromaticBlowfishSwatDynamite".toByteArray(Charsets.US_ASCII)

    private val initialPiTables: Pair<IntArray, Array<IntArray>> by lazy { computeBlowfishPiTables() }

    fun deriveKey(
        passphrase: ByteArray,
        salt: ByteArray,
        rounds: Int,
        keyLen: Int,
    ): ByteArray {
        require(rounds >= 1) { "bcrypt_pbkdf rounds must be >= 1" }
        require(keyLen in 1..(1024)) { "Invalid derived key length: $keyLen" }

        val sha512Pass = sha512(passphrase)
        val stride = (keyLen + BCRYPT_HASHSIZE - 1) / BCRYPT_HASHSIZE
        val out = ByteArray(keyLen)

        val saltWithCount = ByteArray(salt.size + 4)
        System.arraycopy(salt, 0, saltWithCount, 0, salt.size)

        for (block in 1..stride) {
            saltWithCount[salt.size] = ((block ushr 24) and 0xFF).toByte()
            saltWithCount[salt.size + 1] = ((block ushr 16) and 0xFF).toByte()
            saltWithCount[salt.size + 2] = ((block ushr 8) and 0xFF).toByte()
            saltWithCount[salt.size + 3] = (block and 0xFF).toByte()

            var tmp = bcryptHash(sha512Pass, sha512(saltWithCount))
            val accum = tmp.copyOf()

            for (r in 1 until rounds) {
                tmp = bcryptHash(sha512Pass, sha512(tmp))
                for (i in 0 until BCRYPT_HASHSIZE) {
                    accum[i] = (accum[i].toInt() xor tmp[i].toInt()).toByte()
                }
            }

            // OpenBSD bcrypt_pbkdf interleaves output bytes across blocks by stride.
            for (i in 0 until BCRYPT_HASHSIZE) {
                val dest = i * stride + (block - 1)
                if (dest < keyLen) {
                    out[dest] = accum[i]
                }
            }
        }
        sha512Pass.fill(0)
        return out
    }

    private fun bcryptHash(sha2pass: ByteArray, sha2salt: ByteArray): ByteArray {
        val (initP, initS) = initialPiTables
        val p = initP.copyOf()
        val s = Array(4) { i -> initS[i].copyOf() }

        expandKey(p, s, sha2salt, sha2pass)
        repeat(64) {
            expandKey0(p, s, sha2salt)
            expandKey0(p, s, sha2pass)
        }

        val cdata = IntArray(BCRYPT_WORDS)
        for (i in 0 until BCRYPT_WORDS) {
            val o = i * 4
            cdata[i] = ((MAGIC_BYTES[o].toInt() and 0xFF) shl 24) or
                ((MAGIC_BYTES[o + 1].toInt() and 0xFF) shl 16) or
                ((MAGIC_BYTES[o + 2].toInt() and 0xFF) shl 8) or
                (MAGIC_BYTES[o + 3].toInt() and 0xFF)
        }

        repeat(64) {
            var i = 0
            while (i < BCRYPT_WORDS) {
                encipherPair(p, s, cdata, i)
                i += 2
            }
        }

        // OpenBSD bcrypt_hash writes each 32-bit word out in little-endian order.
        val out = ByteArray(BCRYPT_HASHSIZE)
        val bb = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN)
        for (w in cdata) {
            bb.putInt(w)
        }
        return out
    }

    private fun expandKey(p: IntArray, s: Array<IntArray>, data: ByteArray, key: ByteArray) {
        var keyPos = 0
        for (i in 0 until 18) {
            val (w, next) = nextBeWord(key, keyPos)
            keyPos = next
            p[i] = p[i] xor w
        }

        var dataPos = 0
        val block = IntArray(2)
        var i = 0
        while (i < 18) {
            val (d0, n0) = nextBeWord(data, dataPos)
            val (d1, n1) = nextBeWord(data, n0)
            dataPos = n1
            block[0] = block[0] xor d0
            block[1] = block[1] xor d1
            encipherPair(p, s, block, 0)
            p[i] = block[0]
            p[i + 1] = block[1]
            i += 2
        }

        for (box in 0 until 4) {
            var j = 0
            while (j < 256) {
                val (d0, n0) = nextBeWord(data, dataPos)
                val (d1, n1) = nextBeWord(data, n0)
                dataPos = n1
                block[0] = block[0] xor d0
                block[1] = block[1] xor d1
                encipherPair(p, s, block, 0)
                s[box][j] = block[0]
                s[box][j + 1] = block[1]
                j += 2
            }
        }
    }

    private fun expandKey0(p: IntArray, s: Array<IntArray>, key: ByteArray) {
        var keyPos = 0
        for (i in 0 until 18) {
            val (w, next) = nextBeWord(key, keyPos)
            keyPos = next
            p[i] = p[i] xor w
        }

        val block = IntArray(2)
        var i = 0
        while (i < 18) {
            encipherPair(p, s, block, 0)
            p[i] = block[0]
            p[i + 1] = block[1]
            i += 2
        }

        for (box in 0 until 4) {
            var j = 0
            while (j < 256) {
                encipherPair(p, s, block, 0)
                s[box][j] = block[0]
                s[box][j + 1] = block[1]
                j += 2
            }
        }
    }

    private fun nextBeWord(src: ByteArray, startPos: Int): Pair<Int, Int> {
        var pos = startPos
        var word = 0
        repeat(4) {
            word = (word shl 8) or (src[pos].toInt() and 0xFF)
            pos++
            if (pos >= src.size) pos = 0
        }
        return word to pos
    }

    private fun encipherPair(p: IntArray, s: Array<IntArray>, data: IntArray, idx: Int) {
        var xl = data[idx]
        var xr = data[idx + 1]
        xl = xl xor p[0]
        var round = 1
        while (round < 17) {
            xr = xr xor (f(s, xl) xor p[round])
            xl = xl xor (f(s, xr) xor p[round + 1])
            round += 2
        }
        xr = xr xor p[17]
        data[idx] = xr
        data[idx + 1] = xl
    }

    private fun f(s: Array<IntArray>, x: Int): Int {
        val a = (x ushr 24) and 0xFF
        val b = (x ushr 16) and 0xFF
        val c = (x ushr 8) and 0xFF
        val d = x and 0xFF
        return ((s[0][a] + s[1][b]) xor s[2][c]) + s[3][d]
    }

    private fun sha512(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-512").digest(data)

    /**
     * Computes Bruce Schneier's standard Blowfish P-array (18 words) and S-boxes (4 x 256 words)
     * from the fractional hexadecimal digits of pi using Machin's formula.
     */
    private fun computeBlowfishPiTables(): Pair<IntArray, Array<IntArray>> {
        val totalWords = 18 + 4 * 256
        val bits = totalWords * 32 + 128
        val scale = BigInteger.ONE.shiftLeft(bits)

        fun atanInv(k: Long): BigInteger {
            val kBig = BigInteger.valueOf(k)
            val k2 = kBig.multiply(kBig)
            var term = scale.divide(kBig)
            var sum = term
            var n = 1L
            while (term.signum() != 0) {
                term = term.divide(k2)
                val add = term.divide(BigInteger.valueOf(2 * n + 1))
                if (add.signum() == 0) break
                sum = if ((n and 1L) == 1L) sum.subtract(add) else sum.add(add)
                n++
            }
            return sum
        }

        val pi = atanInv(5L).shiftLeft(2).subtract(atanInv(239L)).shiftLeft(2)
        val frac = pi.subtract(BigInteger.valueOf(3).shiftLeft(bits))
        val mask = BigInteger.valueOf(0xFFFFFFFFL)

        val p = IntArray(18)
        val s = Array(4) { IntArray(256) }
        for (i in 0 until totalWords) {
            val shift = bits - (i + 1) * 32
            val word = frac.shiftRight(shift).and(mask).toInt()
            if (i < 18) {
                p[i] = word
            } else {
                val sIdx = i - 18
                s[sIdx / 256][sIdx % 256] = word
            }
        }
        return p to s
    }
}
