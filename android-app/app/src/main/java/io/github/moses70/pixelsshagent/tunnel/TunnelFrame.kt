package io.github.moses70.pixelsshagent.tunnel

import java.nio.ByteBuffer

/**
 * Layer 3 multiplexed tunnel frames carried inside encrypted PSA1 records (docs/PROTOCOL.md).
 */
sealed class TunnelFrame(val typeCode: Byte, val channelId: Int) {
    data class Open(val id: Int) : TunnelFrame(TYPE_OPEN, id)
    data class Data(val id: Int, val payload: ByteArray) : TunnelFrame(TYPE_DATA, id) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Data) return false
            return id == other.id && payload.contentEquals(other.payload)
        }

        override fun hashCode(): Int = 31 * id + payload.contentHashCode()
    }

    data class Close(val id: Int) : TunnelFrame(TYPE_CLOSE, id)
    data object Ping : TunnelFrame(TYPE_PING, 0)
    data object Pong : TunnelFrame(TYPE_PONG, 0)

    fun encode(): ByteArray {
        val payload = when (this) {
            is Data -> this.payload
            else -> EMPTY
        }
        val buf = ByteBuffer.allocate(HEADER_LEN + payload.size)
        buf.put(typeCode)
        buf.putInt(channelId)
        buf.put(payload)
        return buf.array()
    }

    companion object {
        const val TYPE_OPEN: Byte = 0x01
        const val TYPE_DATA: Byte = 0x02
        const val TYPE_CLOSE: Byte = 0x03
        const val TYPE_PING: Byte = 0x04
        const val TYPE_PONG: Byte = 0x05
        const val HEADER_LEN: Int = 5
        private val EMPTY = ByteArray(0)

        fun decode(bytes: ByteArray): TunnelFrame {
            require(bytes.size >= HEADER_LEN) { "TunnelFrame too short: ${bytes.size}" }
            val buf = ByteBuffer.wrap(bytes)
            val type = buf.get()
            val channelId = buf.getInt()
            val payload = ByteArray(bytes.size - HEADER_LEN)
            buf.get(payload)

            return when (type) {
                TYPE_OPEN -> Open(channelId)
                TYPE_DATA -> Data(channelId, payload)
                TYPE_CLOSE -> Close(channelId)
                TYPE_PING -> Ping
                TYPE_PONG -> Pong
                else -> throw IllegalArgumentException("Unknown TunnelFrame type: $type")
            }
        }
    }
}
