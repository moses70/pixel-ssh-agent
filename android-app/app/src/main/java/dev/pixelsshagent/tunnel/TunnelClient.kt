package dev.pixelsshagent.tunnel

import dev.pixelsshagent.crypto.Psa1Protocol
import dev.pixelsshagent.crypto.Psa1SecurityException
import dev.pixelsshagent.crypto.Psa1Session
import dev.pixelsshagent.ssh.SshAgentDispatcher
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.EOFException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

enum class TunnelConnectionState {
    STOPPED,
    CONNECTING,
    CONNECTED,
    AUTH_FAILED,
    ERROR,
}

data class TunnelConfig(
    val host: String = "127.0.0.1",
    val port: Int = 22999,
    val psk: ByteArray,
)

/**
 * Connects as a TCP client to the AVF-forwarded Debian bridge port (`127.0.0.1:<port>`),
 * establishes an authenticated & encrypted PSA1 session, and dispatches incoming SSH agent
 * requests across multiplexed channels.
 */
class TunnelClient(
    private val config: TunnelConfig,
    private val dispatcher: SshAgentDispatcher,
    private val onStateChanged: (TunnelConnectionState, String?) -> Unit,
    private val onLog: (String) -> Unit,
) {
    @Volatile
    private var currentSocket: Socket? = null

    suspend fun runForever() = withContext(Dispatchers.IO) {
        var backoffMs = 1_000L
        while (isActive) {
            onStateChanged(TunnelConnectionState.CONNECTING, "Connecting to ${config.host}:${config.port}")
            val socket = Socket()
            currentSocket = socket
            try {
                socket.tcpNoDelay = true
                socket.keepAlive = true
                socket.connect(InetSocketAddress(config.host, config.port), 5_000)

                val session = Psa1Protocol.handshakeClient(
                    input = socket.getInputStream(),
                    output = socket.getOutputStream(),
                    psk = config.psk,
                )

                backoffMs = 1_000L
                onStateChanged(TunnelConnectionState.CONNECTED, "Connected to ${config.host}:${config.port}")
                onLog("PSA1 tunnel established (${config.host}:${config.port})")

                serveSession(this, session)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Psa1SecurityException) {
                onStateChanged(TunnelConnectionState.AUTH_FAILED, e.message)
                onLog("Auth error: ${e.message}")
                backoffMs = minOf(backoffMs * 2, 15_000L)
            } catch (e: EOFException) {
                onLog("Bridge closed connection")
                onStateChanged(TunnelConnectionState.CONNECTING, "Bridge disconnected, retrying...")
            } catch (e: IOException) {
                onStateChanged(TunnelConnectionState.ERROR, e.message ?: "Connection failed")
                backoffMs = minOf(backoffMs * 2, 10_000L)
            } finally {
                runCatching { socket.close() }
                currentSocket = null
            }

            if (isActive) {
                delay(backoffMs)
            }
        }
        onStateChanged(TunnelConnectionState.STOPPED, null)
    }

    fun closeCurrentSocket() {
        runCatching { currentSocket?.close() }
    }

    private suspend fun serveSession(scope: CoroutineScope, session: Psa1Session) {
        val pingJob: Job = scope.launch(Dispatchers.IO) {
            while (isActive) {
                delay(25_000L)
                runCatching { session.writeRecord(TunnelFrame.Ping.encode()) }
                    .onFailure { closeCurrentSocket() }
            }
        }

        try {
            while (scope.isActive) {
                val raw = session.readRecord()
                val frame = TunnelFrame.decode(raw)
                when (frame) {
                    is TunnelFrame.Open -> {
                        onLog("Channel #${frame.id} opened")
                    }

                    is TunnelFrame.Close -> {
                        onLog("Channel #${frame.id} closed")
                    }

                    is TunnelFrame.Ping -> {
                        session.writeRecord(TunnelFrame.Pong.encode())
                    }

                    is TunnelFrame.Pong -> Unit

                    is TunnelFrame.Data -> {
                        scope.launch(Dispatchers.IO) {
                            val response = dispatcher.handleMessage(frame.payload)
                            runCatching {
                                session.writeRecord(TunnelFrame.Data(frame.id, response).encode())
                            }.onFailure {
                                closeCurrentSocket()
                            }
                        }
                    }
                }
            }
        } finally {
            pingJob.cancel()
        }
    }
}
