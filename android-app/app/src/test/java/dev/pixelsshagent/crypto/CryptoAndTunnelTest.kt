package dev.pixelsshagent.crypto

import dev.pixelsshagent.ssh.SshAgentBackend
import dev.pixelsshagent.ssh.SshAgentDispatcher
import dev.pixelsshagent.ssh.SshAgentMessageType
import dev.pixelsshagent.ssh.SshIdentity
import dev.pixelsshagent.ssh.SshPublicKey
import dev.pixelsshagent.ssh.SshSignature
import dev.pixelsshagent.ssh.SshWireReader
import dev.pixelsshagent.ssh.SshWireWriter
import dev.pixelsshagent.tunnel.TunnelClient
import dev.pixelsshagent.tunnel.TunnelConfig
import dev.pixelsshagent.tunnel.TunnelConnectionState
import dev.pixelsshagent.tunnel.TunnelFrame
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread

class CryptoAndTunnelTest {

    @Test
    fun `X25519 matches RFC 7748 Section 6_1 test vector`() {
        val alicePriv = HexCodec.decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val expectedAlicePub = HexCodec.decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        val bobPriv = HexCodec.decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val expectedBobPub = HexCodec.decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        val expectedShared = HexCodec.decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

        val alicePub = X25519Pure.publicKeyFromPrivate(alicePriv)
        val bobPub = X25519Pure.publicKeyFromPrivate(bobPriv)

        assertArrayEquals(expectedAlicePub, alicePub)
        assertArrayEquals(expectedBobPub, bobPub)
        assertArrayEquals(expectedShared, X25519Pure.scalarMult(alicePriv, bobPub))
        assertArrayEquals(expectedShared, X25519Pure.scalarMult(bobPriv, alicePub))
    }

    @Test
    fun `Ed25519 matches RFC 8032 Section 7_1 official test vectors`() {
        // TEST 1: empty message
        val seed1 = HexCodec.decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        val pub1Expected = HexCodec.decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        val sig1Expected = HexCodec.decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        assertArrayEquals(pub1Expected, Ed25519Pure.publicKeyFromSeed(seed1))
        val sig1 = Ed25519Pure.sign(seed1, ByteArray(0))
        assertArrayEquals(sig1Expected, sig1)
        assertTrue(Ed25519Pure.verify(pub1Expected, ByteArray(0), sig1))
        assertFalse(Ed25519Pure.verify(pub1Expected, byteArrayOf(0), sig1))

        // TEST 2: 1-byte message 0x72
        val seed2 = HexCodec.decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        val pub2Expected = HexCodec.decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        val msg2 = byteArrayOf(0x72)
        val sig2Expected = HexCodec.decode(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        )
        assertArrayEquals(pub2Expected, Ed25519Pure.publicKeyFromSeed(seed2))
        val sig2 = Ed25519Pure.sign(seed2, msg2)
        assertArrayEquals(sig2Expected, sig2)
        assertTrue(Ed25519Pure.verify(pub2Expected, msg2, sig2))

        // TEST 3: 2-byte message 0xaf82
        val seed3 = HexCodec.decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
        val pub3Expected = HexCodec.decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
        val msg3 = HexCodec.decode("af82")
        val sig3Expected = HexCodec.decode(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        )
        assertArrayEquals(pub3Expected, Ed25519Pure.publicKeyFromSeed(seed3))
        val sig3 = Ed25519Pure.sign(seed3, msg3)
        assertArrayEquals(sig3Expected, sig3)
        assertTrue(Ed25519Pure.verify(pub3Expected, msg3, sig3))
    }

    @Test
    fun `HKDF-SHA256 matches RFC 5869 Test Case 1`() {
        val ikm = HexCodec.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val salt = HexCodec.decode("000102030405060708090a0b0c")
        val info = HexCodec.decode("f0f1f2f3f4f5f6f7f8f9")
        val expectedPrk = HexCodec.decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        val expectedOkm = HexCodec.decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )

        val prk = HkdfSha256.extract(salt, ikm)
        assertArrayEquals(expectedPrk, prk)
        assertArrayEquals(expectedOkm, HkdfSha256.expand(prk, info, 42))
    }

    @Test
    fun `PSA1 handshake rejects mismatched PSK`() {
        val pskClient = ByteArray(32) { 0x11 }
        val pskServer = ByteArray(32) { 0x22 }

        val c2sIn = PipedInputStream()
        val c2sOut = PipedOutputStream(c2sIn)
        val s2cIn = PipedInputStream()
        val s2cOut = PipedOutputStream(s2cIn)

        var serverError: Throwable? = null
        val serverThread = thread {
            try {
                Psa1Protocol.handshakeServer(c2sIn, s2cOut, pskServer)
            } catch (t: Throwable) {
                serverError = t
            }
        }

        var clientError: Throwable? = null
        try {
            Psa1Protocol.handshakeClient(s2cIn, c2sOut, pskClient)
        } catch (t: Throwable) {
            clientError = t
        }
        c2sOut.close()
        s2cOut.close()
        serverThread.join(3_000)

        assertTrue("Expected client Psa1SecurityException", clientError is Psa1SecurityException)
        assertTrue("Expected server to fail after client drops", serverError != null)
    }

    @Test
    fun `PSA1 deterministic cross-language key derivation vector`() {
        val psk = ByteArray(32) { it.toByte() }
        val clientPriv = HexCodec.decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val serverPriv = HexCodec.decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val clientNonce = ByteArray(32) { (0xA0 + it).toByte() }
        val serverNonce = ByteArray(32) { (0x50 + it).toByte() }

        val clientPub = X25519Pure.publicKeyFromPrivate(clientPriv)
        val serverPub = X25519Pure.publicKeyFromPrivate(serverPriv)
        val shared = X25519Pure.scalarMult(clientPriv, serverPub)

        val clientHello = Psa1Protocol.buildHelloHeader(clientPub, clientNonce)
        val serverHelloHeader = Psa1Protocol.buildHelloHeader(serverPub, serverNonce)

        val keys = Psa1Protocol.deriveSessionKeys(psk, shared, clientHello, serverHelloHeader)
        val serverMac = Psa1Protocol.computeServerMac(keys.authKey, clientHello, serverHelloHeader)
        val clientMac = Psa1Protocol.computeClientMac(keys.authKey, clientHello, serverHelloHeader)

        // Cross-language deterministic vector (mirrored verbatim in debian-bridge Rust tests)
        assertEquals(
            "a260ea74e49efffaed1e48ac69daf2a3cd57b9f6f9f83a570ba8bf731c7aa35a",
            HexCodec.encode(keys.authKey),
        )
        assertEquals(
            "27b7e7b75f24265f9ec5c3a5557901b68e20c96d2c16586b2a14ba3480ec91d8",
            HexCodec.encode(keys.c2sKey),
        )
        assertEquals(
            "9ca4b9542b91da2ed3cc83f99556f8e5df7f69751ffc91e4c93fecfb611837a9",
            HexCodec.encode(keys.s2cKey),
        )
        assertEquals(
            "810d376f80e164aa535f46e0eb558d9263a46e140252aa1f207bded223e1ba8c",
            HexCodec.encode(serverMac),
        )
        assertEquals(
            "419d07be7caaaa9a1a36098874504a09ae6c2ba14371b41d8a468647e6f16f83",
            HexCodec.encode(clientMac),
        )
    }

    @Test
    fun `end-to-end TCP tunnel dispatches Ed25519 SSH agent signing`() = runBlocking {
        val psk = ByteArray(32) { (0x33 + it).toByte() }
        val seed = Ed25519Pure.generateSeed()
        val rawPub = Ed25519Pure.publicKeyFromSeed(seed)
        val sshPub = SshPublicKey.fromEd25519(rawPub)

        val backend = object : SshAgentBackend {
            override suspend fun listIdentities(): List<SshIdentity> =
                listOf(SshIdentity(sshPub, "test-pixel-key"))

            override suspend fun sign(keyBlob: ByteArray, data: ByteArray, flags: Int): ByteArray? {
                if (!keyBlob.contentEquals(sshPub.blob)) return null
                return SshSignature.encodeEd25519(Ed25519Pure.sign(seed, data))
            }
        }

        val serverSocket = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = serverSocket.localPort

        val client = TunnelClient(
            config = TunnelConfig(host = "127.0.0.1", port = port, psk = psk),
            dispatcher = SshAgentDispatcher(backend),
            onStateChanged = { state: TunnelConnectionState, _ -> },
            onLog = {},
        )

        val clientJob = launch(Dispatchers.IO) { client.runForever() }

        try {
            val accepted = serverSocket.accept()
            accepted.use { sock ->
                val session = Psa1Protocol.handshakeServer(
                    input = sock.getInputStream(),
                    output = sock.getOutputStream(),
                    psk = psk,
                )

                // Ping / Pong
                session.writeRecord(TunnelFrame.Ping.encode())
                assertEquals(TunnelFrame.Pong, TunnelFrame.decode(session.readRecord()))

                // Open channel #7 and request identities
                session.writeRecord(TunnelFrame.Open(7).encode())
                session.writeRecord(
                    TunnelFrame.Data(7, byteArrayOf(SshAgentMessageType.SSH_AGENTC_REQUEST_IDENTITIES.toByte()))
                        .encode(),
                )
                val idFrame = TunnelFrame.decode(session.readRecord()) as TunnelFrame.Data
                assertEquals(7, idFrame.id)
                val idReader = SshWireReader(idFrame.payload)
                assertEquals(SshAgentMessageType.SSH_AGENT_IDENTITIES_ANSWER, idReader.readByte())
                assertEquals(1, idReader.readUint32())
                assertArrayEquals(sshPub.blob, idReader.readBytes())
                assertEquals("test-pixel-key", idReader.readString())

                // Sign a challenge on channel #7
                val challenge = "openssh-session-auth-payload".toByteArray()
                val signReq = SshWireWriter()
                    .writeByte(SshAgentMessageType.SSH_AGENTC_SIGN_REQUEST)
                    .writeBytes(sshPub.blob)
                    .writeBytes(challenge)
                    .writeUint32(0)
                    .toByteArray()
                session.writeRecord(TunnelFrame.Data(7, signReq).encode())

                val signFrame = TunnelFrame.decode(session.readRecord()) as TunnelFrame.Data
                val signReader = SshWireReader(signFrame.payload)
                assertEquals(SshAgentMessageType.SSH_AGENT_SIGN_RESPONSE, signReader.readByte())
                val sigBlob = signReader.readBytes()

                val sigBlobReader = SshWireReader(sigBlob)
                assertEquals("ssh-ed25519", sigBlobReader.readString())
                val rawSig = sigBlobReader.readBytes()
                assertTrue(Ed25519Pure.verify(rawPub, challenge, rawSig))

                session.writeRecord(TunnelFrame.Close(7).encode())
            }
        } finally {
            clientJob.cancel()
            client.closeCurrentSocket()
            serverSocket.close()
        }
    }
}
