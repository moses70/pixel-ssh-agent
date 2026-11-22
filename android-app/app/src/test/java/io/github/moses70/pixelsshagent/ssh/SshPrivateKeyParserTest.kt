package io.github.moses70.pixelsshagent.ssh

import io.github.moses70.pixelsshagent.crypto.Ed25519Pure
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec

class SshPrivateKeyParserTest {

    // Real keys generated via OpenSSH `ssh-keygen` specifically for unit testing.
    private val ed25519PlainPem = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACAiHDTL84Dtc1QypzErzILofRC8bwD61FXxcvYibK8WjwAAAJDpYwf26WMH
        9gAAAAtzc2gtZWQyNTUxOQAAACAiHDTL84Dtc1QypzErzILofRC8bwD61FXxcvYibK8Wjw
        AAAECBkJjqQ8LetXjmM52BhQImqfga8l2i1bNYOP2lM9FKYCIcNMvzgO1zVDKnMSvMguh9
        ELxvAPrUVfFy9iJsrxaPAAAADWVkLXBsYWluQHRlc3Q=
        -----END OPENSSH PRIVATE KEY-----
    """.trimIndent()

    private val ed25519PlainPub =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICIcNMvzgO1zVDKnMSvMguh9ELxvAPrUVfFy9iJsrxaP ed-plain@test"

    private val ed25519EncryptedPem = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDAQUneQj
        CQGmhwoQBHz6L6AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIGl8LCsKlhKOdB/f
        etxy+YClcjmtfCj1H5H5Uy1Uqyh6AAAAkAwXSMM+6Z8RkN9YmKd9Pyd/Ly+LE25sl+/+nE
        RwNdGQHuWjF8yOAiHgWR2TmABtLFB0zaLfvVHERUFDkcNP/rnqS++J2ibIeP6fsdHjduEP
        wpI4xeSJ9gWjbe5ZJZue0VRZU3clA0u1ZZYY0sKDHKBl4BgtqLX9VPNvjQE25d00lFciSs
        7UxvvFpcntnp8j3A==
        -----END OPENSSH PRIVATE KEY-----
    """.trimIndent()

    private val ed25519EncryptedPub =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGl8LCsKlhKOdB/fetxy+YClcjmtfCj1H5H5Uy1Uqyh6 ed-enc@test"

    private val ecdsaPlainPem = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
        1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTLxAUyMM6ZasuklUJUHhl+8kKYS2YK
        GcmOg4d5THXnGk4KxxO9Qx3I2Vv2Iec5wmECFRp4CGCPEcuW67u+laRvAAAAsPQCqr/0Aq
        q/AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMvEBTIwzplqy6SV
        QlQeGX7yQphLZgoZyY6Dh3lMdecaTgrHE71DHcjZW/Yh5znCYQIVGngIYI8Ry5bru76VpG
        8AAAAhALqxAQkZQPE0qsatC2c1p9YryN9n56aNmxoGJcMzrKZZAAAAEGVjZHNhLXBsYWlu
        QHRlc3QBAgMEBQYH
        -----END OPENSSH PRIVATE KEY-----
    """.trimIndent()

    private val ecdsaPlainPub =
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMvEBTIwzplqy6SVQlQeGX7yQphLZgoZyY6Dh3lMdecaTgrHE71DHcjZW/Yh5znCYQIVGngIYI8Ry5bru76VpG8= ecdsa-plain@test"

    @Test
    fun `parses unencrypted OpenSSH Ed25519 key and produces valid signature`() {
        assertFalse(SshPrivateKeyParser.isEncryptedOpenSshKey(ed25519PlainPem))
        val parsed = SshPrivateKeyParser.parse(ed25519PlainPem)
        try {
            assertEquals(SshKeyAlgorithm.ED25519, parsed.algorithm)
            assertEquals("ed-plain@test", parsed.embeddedComment)
            assertEquals(ed25519PlainPub, parsed.publicKey.toAuthorizedKeysLine(parsed.embeddedComment))

            val msg = "ssh-agent-import-test".toByteArray()
            val sig = Ed25519Pure.sign(parsed.secretMaterial, msg)
            val rawPub = Ed25519Pure.publicKeyFromSeed(parsed.secretMaterial)
            assertTrue(Ed25519Pure.verify(rawPub, msg, sig))
        } finally {
            parsed.wipeSecret()
        }
    }

    @Test
    fun `decrypts passphrase-protected OpenSSH Ed25519 key via bcrypt_pbkdf and aes256-ctr`() {
        assertTrue(SshPrivateKeyParser.isEncryptedOpenSshKey(ed25519EncryptedPem))

        // Wrong passphrase must fail
        val wrongResult = runCatching { SshPrivateKeyParser.parse(ed25519EncryptedPem, "wrongpass") }
        assertTrue(wrongResult.isFailure)

        // Missing passphrase must fail
        val missingResult = runCatching { SshPrivateKeyParser.parse(ed25519EncryptedPem, null) }
        assertTrue(missingResult.isFailure)

        // Correct passphrase must succeed and match ssh-keygen .pub output exactly
        val parsed = SshPrivateKeyParser.parse(ed25519EncryptedPem, "secret123")
        try {
            assertEquals(SshKeyAlgorithm.ED25519, parsed.algorithm)
            assertEquals("ed-enc@test", parsed.embeddedComment)
            assertEquals(ed25519EncryptedPub, parsed.publicKey.toAuthorizedKeysLine(parsed.embeddedComment))

            val msg = "encrypted-import-verify".toByteArray()
            val sig = Ed25519Pure.sign(parsed.secretMaterial, msg)
            val rawPub = Ed25519Pure.publicKeyFromSeed(parsed.secretMaterial)
            assertTrue(Ed25519Pure.verify(rawPub, msg, sig))
        } finally {
            parsed.wipeSecret()
        }
    }

    @Test
    fun `parses unencrypted OpenSSH ECDSA P-256 key and signs with JCA`() {
        assertFalse(SshPrivateKeyParser.isEncryptedOpenSshKey(ecdsaPlainPem))
        val parsed = SshPrivateKeyParser.parse(ecdsaPlainPem)
        try {
            assertEquals(SshKeyAlgorithm.ECDSA_P256, parsed.algorithm)
            assertEquals("ecdsa-plain@test", parsed.embeddedComment)
            assertEquals(ecdsaPlainPub, parsed.publicKey.toAuthorizedKeysLine(parsed.embeddedComment))

            // Sign with JCA using extracted scalar d and verify with extracted public key point
            val params = AlgorithmParameters.getInstance("EC").apply {
                init(ECGenParameterSpec("secp256r1"))
            }
            val ecSpec = params.getParameterSpec(ECParameterSpec::class.java)
            val kf = KeyFactory.getInstance("EC")
            val privKey = kf.generatePrivate(ECPrivateKeySpec(BigInteger(1, parsed.secretMaterial), ecSpec))

            val reader = SshWireReader(parsed.publicKey.blob)
            reader.readString() // algo
            reader.readString() // curve
            val q = reader.readBytes()
            val pubKey = kf.generatePublic(
                ECPublicKeySpec(
                    ECPoint(BigInteger(1, q.copyOfRange(1, 33)), BigInteger(1, q.copyOfRange(33, 65))),
                    ecSpec,
                ),
            )

            val payload = "ecdsa-import-sign-check".toByteArray()
            val derSig = Signature.getInstance("SHA256withECDSA").run {
                initSign(privKey)
                update(payload)
                sign()
            }
            val verified = Signature.getInstance("SHA256withECDSA").run {
                initVerify(pubKey)
                update(payload)
                verify(derSig)
            }
            assertTrue(verified)
        } finally {
            parsed.wipeSecret()
        }
    }

    @Test
    fun `parses raw 64-hex Ed25519 seed`() {
        // RFC 8032 TEST 1 seed
        val parsed = SshPrivateKeyParser.parse(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )
        try {
            assertEquals(SshKeyAlgorithm.ED25519, parsed.algorithm)
            assertTrue(parsed.publicKey.toAuthorizedKeysLine().startsWith("ssh-ed25519 AAAA"))
        } finally {
            parsed.wipeSecret()
        }
    }
}
