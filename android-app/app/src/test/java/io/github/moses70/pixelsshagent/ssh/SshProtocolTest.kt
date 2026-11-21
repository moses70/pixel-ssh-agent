package io.github.moses70.pixelsshagent.ssh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class SshProtocolTest {

    @Test
    fun `mpint encoding matches RFC 4251 examples`() {
        // RFC 4251 Section 5 examples:
        // 0 -> 00 00 00 00
        assertArrayEquals(
            byteArrayOf(0, 0, 0, 0),
            SshWireWriter().writeMpint(BigInteger.ZERO).toByteArray(),
        )
        // 0x9a378f9b2e332a7 -> 00 00 00 08 09 a3 78 f9 b2 e3 32 a7
        assertArrayEquals(
            hexToBytes("0000000809a378f9b2e332a7"),
            SshWireWriter().writeMpint(BigInteger("9a378f9b2e332a7", 16)).toByteArray(),
        )
        // 0x80 -> 00 00 00 02 00 80 (leading zero required when MSB set)
        assertArrayEquals(
            hexToBytes("000000020080"),
            SshWireWriter().writeMpint(BigInteger.valueOf(0x80)).toByteArray(),
        )
    }

    @Test
    fun `ecdsa p256 public key blob roundtrip and authorized_keys format`() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val pub = SshPublicKey.fromEcdsaP256(kp.public as ECPublicKey)

        val parsed = SshPublicKey.fromBlob(pub.blob)
        assertEquals(pub, parsed)
        assertEquals(SshKeyAlgorithm.ECDSA_P256, parsed.algorithm)
        assertTrue(pub.sha256Fingerprint().startsWith("SHA256:"))
        assertTrue(pub.toAuthorizedKeysLine("pixel@debian").startsWith("ecdsa-sha2-nistp256 AAAA"))
        assertTrue(pub.toAuthorizedKeysLine("pixel@debian").endsWith(" pixel@debian"))
    }

    @Test
    fun `ed25519 public key blob matches OpenSSH exact layout`() {
        val rawPub = ByteArray(32) { (it + 1).toByte() }
        val pub = SshPublicKey.fromEd25519(rawPub)

        val reader = SshWireReader(pub.blob)
        assertEquals("ssh-ed25519", reader.readString())
        assertArrayEquals(rawPub, reader.readBytes())
        reader.ensureConsumed()

        assertEquals(pub, SshPublicKey.fromBlob(pub.blob))
    }

    @Test
    fun `der ecdsa signature converts cleanly to SSH ecdsa-sha2-nistp256 blob`() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val data = "ssh-userauth-challenge".toByteArray()

        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(kp.private)
        sig.update(data)
        val der = sig.sign()

        val sshSig = SshSignature.encodeEcdsaP256FromDer(der)
        val outer = SshWireReader(sshSig)
        assertEquals("ecdsa-sha2-nistp256", outer.readString())
        val innerBytes = outer.readBytes()
        outer.ensureConsumed()

        val inner = SshWireReader(innerBytes)
        val r = inner.readMpint()
        val s = inner.readMpint()
        inner.ensureConsumed()

        assertTrue(r > BigInteger.ZERO)
        assertTrue(s > BigInteger.ZERO)
    }

    @Test
    fun `agent dispatcher handles REQUEST_IDENTITIES, SIGN_REQUEST, and unknown types`() = runTest {
        val rawPub = ByteArray(32) { 0x42 }
        val pubKey = SshPublicKey.fromEd25519(rawPub)
        val fakeSig = SshSignature.encodeEd25519(ByteArray(64) { 0x7A })

        val backend = object : SshAgentBackend {
            override suspend fun listIdentities(): List<SshIdentity> =
                listOf(SshIdentity(pubKey, "pixel-ed25519"))

            override suspend fun sign(keyBlob: ByteArray, data: ByteArray, flags: Int): ByteArray? =
                if (keyBlob.contentEquals(pubKey.blob)) fakeSig else null
        }

        val dispatcher = SshAgentDispatcher(backend)

        // 1. REQUEST_IDENTITIES
        val idsResp = dispatcher.handleMessage(
            byteArrayOf(SshAgentMessageType.SSH_AGENTC_REQUEST_IDENTITIES.toByte()),
        )
        val idReader = SshWireReader(idsResp)
        assertEquals(SshAgentMessageType.SSH_AGENT_IDENTITIES_ANSWER, idReader.readByte())
        assertEquals(1, idReader.readUint32())
        assertArrayEquals(pubKey.blob, idReader.readBytes())
        assertEquals("pixel-ed25519", idReader.readString())
        idReader.ensureConsumed()

        // 2. SIGN_REQUEST (valid key)
        val signReq = SshWireWriter()
            .writeByte(SshAgentMessageType.SSH_AGENTC_SIGN_REQUEST)
            .writeBytes(pubKey.blob)
            .writeBytes("challenge-payload".toByteArray())
            .writeUint32(0)
            .toByteArray()
        val signResp = dispatcher.handleMessage(signReq)
        val signReader = SshWireReader(signResp)
        assertEquals(SshAgentMessageType.SSH_AGENT_SIGN_RESPONSE, signReader.readByte())
        assertArrayEquals(fakeSig, signReader.readBytes())
        signReader.ensureConsumed()

        // 3. SIGN_REQUEST (unknown key -> FAILURE)
        val badSignReq = SshWireWriter()
            .writeByte(SshAgentMessageType.SSH_AGENTC_SIGN_REQUEST)
            .writeBytes(byteArrayOf(1, 2, 3))
            .writeBytes("challenge".toByteArray())
            .writeUint32(0)
            .toByteArray()
        assertArrayEquals(
            byteArrayOf(SshAgentMessageType.SSH_AGENT_FAILURE.toByte()),
            dispatcher.handleMessage(badSignReq),
        )

        // 4. EXTENSION -> EXTENSION_FAILURE
        val extResp = dispatcher.handleMessage(
            SshWireWriter()
                .writeByte(SshAgentMessageType.SSH_AGENTC_EXTENSION)
                .writeString("session-bind@openssh.com")
                .toByteArray(),
        )
        assertArrayEquals(
            byteArrayOf(SshAgentMessageType.SSH_AGENT_EXTENSION_FAILURE.toByte()),
            extResp,
        )
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "")
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
