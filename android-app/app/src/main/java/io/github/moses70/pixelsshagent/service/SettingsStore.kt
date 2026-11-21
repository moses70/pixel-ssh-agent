package io.github.moses70.pixelsshagent.service

import android.content.Context
import io.github.moses70.pixelsshagent.crypto.HexCodec
import java.security.SecureRandom

data class AgentSettings(
    val host: String = "127.0.0.1",
    val port: Int = 22999,
    val pskHex: String,
    val unlockWindowMinutes: Int = 0,
) {
    fun pskBytesOrNull(): ByteArray? = runCatching {
        val bytes = HexCodec.decode(pskHex)
        if (bytes.size == 32) bytes else null
    }.getOrNull()
}

class SettingsStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun load(): AgentSettings {
        val existingPsk = prefs.getString(KEY_PSK_HEX, null)
        val pskHex = if (existingPsk != null && existingPsk.length == 64) {
            existingPsk
        } else {
            generateNewPskHex().also {
                prefs.edit().putString(KEY_PSK_HEX, it).apply()
            }
        }
        return AgentSettings(
            host = prefs.getString(KEY_HOST, "127.0.0.1") ?: "127.0.0.1",
            port = prefs.getInt(KEY_PORT, 22999),
            pskHex = pskHex,
            unlockWindowMinutes = prefs.getInt(KEY_UNLOCK_MINUTES, 0),
        )
    }

    fun save(settings: AgentSettings) {
        prefs.edit()
            .putString(KEY_HOST, settings.host.trim().ifEmpty { "127.0.0.1" })
            .putInt(KEY_PORT, settings.port.coerceIn(1024, 65535))
            .putString(KEY_PSK_HEX, settings.pskHex.trim().lowercase())
            .putInt(KEY_UNLOCK_MINUTES, settings.unlockWindowMinutes.coerceIn(0, 60))
            .apply()
    }

    fun generateNewPskHex(): String {
        val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        return HexCodec.encode(bytes)
    }

    companion object {
        private const val PREFS_NAME = "pixel_ssh_agent_settings"
        private const val KEY_HOST = "host"
        private const val KEY_PORT = "port"
        private const val KEY_PSK_HEX = "psk_hex"
        private const val KEY_UNLOCK_MINUTES = "unlock_minutes"
    }
}
