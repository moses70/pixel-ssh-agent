package io.github.moses70.pixelsshagent.service

import android.content.Context
import io.github.moses70.pixelsshagent.crypto.KeyRepository
import io.github.moses70.pixelsshagent.crypto.ManagedKey
import io.github.moses70.pixelsshagent.ssh.SshAgentBackend
import io.github.moses70.pixelsshagent.ssh.SshIdentity
import io.github.moses70.pixelsshagent.ssh.SshKeyAlgorithm
import io.github.moses70.pixelsshagent.tunnel.TunnelConnectionState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

data class AgentLogEntry(
    val timestamp: String,
    val message: String,
)

data class PendingSignRequest(
    val requestId: String,
    val keyComment: String,
    val fingerprint: String,
    val algorithm: SshKeyAlgorithm,
    val payloadBytes: Int,
    internal val decision: CompletableDeferred<Boolean>,
)

/**
 * Process-wide coordinator bridging the ForegroundService tunnel, KeyRepository,
 * biometric approval prompts, and Compose UI state.
 */
class AgentCoordinator private constructor(context: Context) : SshAgentBackend {
    private val keyRepository = KeyRepository(context)
    private val settingsStore = SettingsStore(context)
    private val approvalMutex = Mutex()
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    private val _settings = MutableStateFlow(settingsStore.load())
    val settings: StateFlow<AgentSettings> = _settings.asStateFlow()

    private val _keys = MutableStateFlow(keyRepository.listKeys())
    val keys: StateFlow<List<ManagedKey>> = _keys.asStateFlow()

    private val _connectionState = MutableStateFlow(TunnelConnectionState.STOPPED)
    val connectionState: StateFlow<TunnelConnectionState> = _connectionState.asStateFlow()

    private val _statusMessage = MutableStateFlow<String?>(null)
    val statusMessage: StateFlow<String?> = _statusMessage.asStateFlow()

    private val _logs = MutableStateFlow<List<AgentLogEntry>>(emptyList())
    val logs: StateFlow<List<AgentLogEntry>> = _logs.asStateFlow()

    private val _pendingSignRequest = MutableStateFlow<PendingSignRequest?>(null)
    val pendingSignRequest: StateFlow<PendingSignRequest?> = _pendingSignRequest.asStateFlow()

    @Volatile
    private var unlockedUntilMs: Long = 0L

    @Volatile
    var onSignPromptRequested: ((PendingSignRequest) -> Unit)? = null

    fun updateSettings(newSettings: AgentSettings) {
        settingsStore.save(newSettings)
        val loaded = settingsStore.load()
        _settings.value = loaded
        val mins = loaded.unlockWindowMinutes
        if (mins == 0) {
            unlockedUntilMs = 0L
        } else if (unlockedUntilMs > 0L) {
            val maxAllowed = System.currentTimeMillis() + mins * 60_000L
            if (unlockedUntilMs > maxAllowed) {
                unlockedUntilMs = maxAllowed
            }
        }
        val unlockText = if (mins == 0) "Every sign" else "$mins min"
        appendLog("Settings updated (${loaded.host}:${loaded.port}, unlock: $unlockText)")
    }

    fun regeneratePsk(): String {
        val newPsk = settingsStore.generateNewPskHex()
        updateSettings(_settings.value.copy(pskHex = newPsk))
        appendLog("Generated new 256-bit pairing PSK")
        return newPsk
    }

    fun createKey(comment: String, algorithm: SshKeyAlgorithm, requireBiometric: Boolean): ManagedKey {
        val key = keyRepository.createKey(comment, algorithm, requireBiometric)
        _keys.value = keyRepository.listKeys()
        val backing = if (key.strongBoxBacked) "StrongBox" else algorithm.displayName
        appendLog("Created key '${key.comment}' ($backing)")
        return key
    }

    fun importKey(
        rawKeyInput: String,
        passphrase: String?,
        commentOverride: String?,
        requireBiometric: Boolean,
    ): ManagedKey {
        val key = keyRepository.importKey(rawKeyInput, passphrase, commentOverride, requireBiometric)
        _keys.value = keyRepository.listKeys()
        appendLog("Imported ${key.algorithm.sshName} key '${key.comment}'")
        return key
    }

    fun deleteKey(id: String) {
        val target = _keys.value.firstOrNull { it.id == id }
        if (keyRepository.deleteKey(id)) {
            _keys.value = keyRepository.listKeys()
            appendLog("Deleted key '${target?.comment ?: id}'")
        }
    }

    fun updateConnectionState(state: TunnelConnectionState, message: String?) {
        _connectionState.value = state
        _statusMessage.value = message
    }

    fun appendLog(message: String) {
        val entry = AgentLogEntry(timeFormat.format(Date()), message)
        _logs.update { current -> (listOf(entry) + current).take(MAX_LOG_ENTRIES) }
    }

    fun resolvePendingSign(requestId: String, approved: Boolean) {
        val pending = _pendingSignRequest.value
        if (pending != null && pending.requestId == requestId) {
            if (approved) {
                val mins = _settings.value.unlockWindowMinutes
                unlockedUntilMs = if (mins > 0) {
                    System.currentTimeMillis() + mins * 60_000L
                } else {
                    0L
                }
            }
            pending.decision.complete(approved)
            _pendingSignRequest.value = null
        }
    }

    fun lockNow() {
        unlockedUntilMs = 0L
        appendLog("Agent unlock window cleared")
    }

    private fun isCurrentlyUnlocked(): Boolean {
        val mins = _settings.value.unlockWindowMinutes
        return mins > 0 && System.currentTimeMillis() < unlockedUntilMs
    }

    override suspend fun listIdentities(): List<SshIdentity> {
        val list = keyRepository.listKeys()
        appendLog("REQUEST_IDENTITIES → returned ${list.size} key(s)")
        return list.map { SshIdentity(it.publicKey, it.comment) }
    }

    override suspend fun sign(keyBlob: ByteArray, data: ByteArray, flags: Int): ByteArray? {
        val key = keyRepository.findByBlob(keyBlob)
        if (key == null) {
            appendLog("SIGN_REQUEST rejected: unknown key")
            return null
        }

        if (key.requireBiometric && !isCurrentlyUnlocked()) {
            val approved = requestUserApproval(key, data.size)
            if (!approved) {
                appendLog("SIGN_REQUEST denied/timed out for '${key.comment}'")
                return null
            }
        }

        return try {
            val signature = keyRepository.sign(key, data)
            appendLog("Signed ${data.size}B with '${key.comment}' (${key.algorithm.sshName})")
            signature
        } catch (e: Exception) {
            appendLog("Signing failed for '${key.comment}': ${e.message}")
            null
        }
    }

    private suspend fun requestUserApproval(key: ManagedKey, payloadBytes: Int): Boolean {
        return approvalMutex.withLock {
            if (isCurrentlyUnlocked()) {
                return@withLock true
            }
            val deferred = CompletableDeferred<Boolean>()
            val request = PendingSignRequest(
                requestId = UUID.randomUUID().toString(),
                keyComment = key.comment,
                fingerprint = key.fingerprint,
                algorithm = key.algorithm,
                payloadBytes = payloadBytes,
                decision = deferred,
            )
            _pendingSignRequest.value = request
            appendLog("Waiting for biometric approval: '${key.comment}'...")
            onSignPromptRequested?.invoke(request)

            val result = withTimeoutOrNull(APPROVAL_TIMEOUT_MS) { deferred.await() } ?: false
            if (_pendingSignRequest.value?.requestId == request.requestId) {
                _pendingSignRequest.value = null
            }
            result
        }
    }

    companion object {
        private const val MAX_LOG_ENTRIES = 100
        private const val APPROVAL_TIMEOUT_MS = 60_000L

        @Volatile
        private var instance: AgentCoordinator? = null

        fun get(context: Context): AgentCoordinator {
            return instance ?: synchronized(this) {
                instance ?: AgentCoordinator(context.applicationContext).also { instance = it }
            }
        }
    }
}
