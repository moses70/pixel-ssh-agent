package io.github.moses70.pixelsshagent.ssh

/**
 * Pure Kotlin implementation of the OpenSSH Agent Protocol (`draft-miller-ssh-agent`).
 *
 * Operates on unframed SSH agent message payloads (`[byte msg_type][body]`),
 * because outer 4-byte framing is stripped/re-added by the Debian Unix socket bridge.
 */
object SshAgentMessageType {
    const val SSH_AGENT_FAILURE = 5
    const val SSH_AGENT_SUCCESS = 6
    const val SSH_AGENTC_REQUEST_IDENTITIES = 11
    const val SSH_AGENT_IDENTITIES_ANSWER = 12
    const val SSH_AGENTC_SIGN_REQUEST = 13
    const val SSH_AGENT_SIGN_RESPONSE = 14
    const val SSH_AGENTC_EXTENSION = 27
    const val SSH_AGENT_EXTENSION_FAILURE = 28
}

data class SshIdentity(
    val publicKey: SshPublicKey,
    val comment: String,
)

interface SshAgentBackend {
    suspend fun listIdentities(): List<SshIdentity>

    /**
     * Signs [data] using the key matching [keyBlob].
     * Returns the OpenSSH wire signature blob, or `null` if key is unknown or user rejected.
     */
    suspend fun sign(keyBlob: ByteArray, data: ByteArray, flags: Int): ByteArray?
}

class SshAgentDispatcher(
    private val backend: SshAgentBackend,
) {
    suspend fun handleMessage(message: ByteArray): ByteArray {
        if (message.isEmpty()) {
            return failure()
        }
        val reader = SshWireReader(message)
        val msgType = reader.readByte()

        return try {
            when (msgType) {
                SshAgentMessageType.SSH_AGENTC_REQUEST_IDENTITIES -> {
                    reader.ensureConsumed()
                    val identities = backend.listIdentities()
                    encodeIdentitiesAnswer(identities)
                }

                SshAgentMessageType.SSH_AGENTC_SIGN_REQUEST -> {
                    val keyBlob = reader.readBytes()
                    val data = reader.readBytes()
                    val flags = reader.readUint32()
                    reader.ensureConsumed()

                    val sigBlob = backend.sign(keyBlob, data, flags)
                    if (sigBlob != null) {
                        encodeSignResponse(sigBlob)
                    } else {
                        failure()
                    }
                }

                SshAgentMessageType.SSH_AGENTC_EXTENSION -> {
                    // Explicitly advertise unsupported extension per draft-miller-ssh-agent
                    byteArrayOf(SshAgentMessageType.SSH_AGENT_EXTENSION_FAILURE.toByte())
                }

                else -> failure()
            }
        } catch (_: SshWireException) {
            failure()
        } catch (_: Exception) {
            failure()
        }
    }

    companion object {
        fun failure(): ByteArray = byteArrayOf(SshAgentMessageType.SSH_AGENT_FAILURE.toByte())

        fun success(): ByteArray = byteArrayOf(SshAgentMessageType.SSH_AGENT_SUCCESS.toByte())

        fun encodeIdentitiesAnswer(identities: List<SshIdentity>): ByteArray {
            val writer = SshWireWriter()
                .writeByte(SshAgentMessageType.SSH_AGENT_IDENTITIES_ANSWER)
                .writeUint32(identities.size)
            for (id in identities) {
                writer.writeBytes(id.publicKey.blob)
                writer.writeString(id.comment)
            }
            return writer.toByteArray()
        }

        fun encodeSignResponse(signatureBlob: ByteArray): ByteArray {
            return SshWireWriter()
                .writeByte(SshAgentMessageType.SSH_AGENT_SIGN_RESPONSE)
                .writeBytes(signatureBlob)
                .toByteArray()
        }
    }
}
