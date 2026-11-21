package io.github.moses70.pixelsshagent.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import io.github.moses70.pixelsshagent.ssh.SshAgentDispatcher
import io.github.moses70.pixelsshagent.tunnel.TunnelClient
import io.github.moses70.pixelsshagent.tunnel.TunnelConfig
import io.github.moses70.pixelsshagent.tunnel.TunnelConnectionState
import io.github.moses70.pixelsshagent.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * ForegroundService keeping the encrypted PSA1 TCP tunnel connected to the Debian VM bridge
 * while the user works inside the Pixel Linux Terminal.
 */
class AgentForegroundService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var coordinator: AgentCoordinator
    private lateinit var notificationManager: NotificationManager

    private var tunnelJob: Job? = null
    private var tunnelClient: TunnelClient? = null

    override fun onCreate() {
        super.onCreate()
        coordinator = AgentCoordinator.get(this)
        notificationManager = getSystemService(NotificationManager::class.java)
        createNotificationChannels()

        coordinator.onSignPromptRequested = { request ->
            showSignApprovalNotification(request)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }

            ACTION_DENY_SIGN -> {
                val reqId = intent.getStringExtra(EXTRA_REQUEST_ID)
                if (reqId != null) {
                    coordinator.resolvePendingSign(reqId, approved = false)
                }
                notificationManager.cancel(NOTIF_ID_SIGN_PROMPT)
                return START_STICKY
            }

            else -> {
                startForegroundWithNotification("Starting tunnel...")
                startTunnel()
                return START_STICKY
            }
        }
    }

    override fun onDestroy() {
        coordinator.onSignPromptRequested = null
        stopTunnel()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startTunnel() {
        stopTunnel()
        val settings = coordinator.settings.value
        val psk = settings.pskBytesOrNull()
        if (psk == null) {
            coordinator.updateConnectionState(TunnelConnectionState.AUTH_FAILED, "Invalid 64-hex PSK")
            updateStatusNotification("Invalid pairing PSK")
            return
        }

        val client = TunnelClient(
            config = TunnelConfig(host = settings.host, port = settings.port, psk = psk),
            dispatcher = SshAgentDispatcher(coordinator),
            onStateChanged = { state, msg ->
                coordinator.updateConnectionState(state, msg)
                val summary = when (state) {
                    TunnelConnectionState.CONNECTED -> "Connected (${settings.host}:${settings.port})"
                    TunnelConnectionState.CONNECTING -> "Waiting for Debian bridge (:${settings.port})..."
                    TunnelConnectionState.AUTH_FAILED -> "Auth failed — check PSK"
                    TunnelConnectionState.ERROR -> "Reconnecting (${msg ?: "error"})"
                    TunnelConnectionState.STOPPED -> "Stopped"
                }
                updateStatusNotification(summary)
            },
            onLog = { coordinator.appendLog(it) },
        )
        tunnelClient = client
        tunnelJob = serviceScope.launch {
            client.runForever()
        }
    }

    private fun stopTunnel() {
        tunnelJob?.cancel()
        tunnelClient?.closeCurrentSocket()
        tunnelJob = null
        tunnelClient = null
        coordinator.updateConnectionState(TunnelConnectionState.STOPPED, null)
        notificationManager.cancel(NOTIF_ID_SIGN_PROMPT)
    }

    private fun startForegroundWithNotification(text: String) {
        val notification = buildStatusNotification(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIF_ID_STATUS,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIF_ID_STATUS, notification)
        }
    }

    private fun updateStatusNotification(text: String) {
        notificationManager.notify(NOTIF_ID_STATUS, buildStatusNotification(text))
    }

    private fun buildStatusNotification(text: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, AgentForegroundService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        return NotificationCompat.Builder(this, CHANNEL_STATUS)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Pixel SSH Agent")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(openIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", stopIntent)
            .build()
    }

    private fun showSignApprovalNotification(request: PendingSignRequest) {
        val openIntent = PendingIntent.getActivity(
            this,
            2,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val denyIntent = PendingIntent.getService(
            this,
            3,
            Intent(this, AgentForegroundService::class.java).apply {
                action = ACTION_DENY_SIGN
                putExtra(EXTRA_REQUEST_ID, request.requestId)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val notif = NotificationCompat.Builder(this, CHANNEL_SIGN_REQUEST)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("SSH Sign Request: ${request.keyComment}")
            .setContentText("Tap to verify with biometrics (${request.algorithm.sshName})")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setAutoCancel(true)
            .setTimeoutAfter(60_000L)
            .setContentIntent(openIntent)
            .addAction(android.R.drawable.ic_delete, "Deny", denyIntent)
            .build()

        notificationManager.notify(NOTIF_ID_SIGN_PROMPT, notif)
    }

    private fun createNotificationChannels() {
        val statusChannel = NotificationChannel(
            CHANNEL_STATUS,
            "SSH Agent Service",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Keeps the encrypted tunnel to the Pixel Linux Terminal active"
        }
        val signChannel = NotificationChannel(
            CHANNEL_SIGN_REQUEST,
            "SSH Sign Requests",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Biometric confirmation prompts for SSH authentication"
        }
        notificationManager.createNotificationChannel(statusChannel)
        notificationManager.createNotificationChannel(signChannel)
    }

    companion object {
        private const val CHANNEL_STATUS = "psa_status"
        private const val CHANNEL_SIGN_REQUEST = "psa_sign_request"
        private const val NOTIF_ID_STATUS = 1001
        private const val NOTIF_ID_SIGN_PROMPT = 1002

        const val ACTION_START = "io.github.moses70.pixelsshagent.action.START"
        const val ACTION_STOP = "io.github.moses70.pixelsshagent.action.STOP"
        const val ACTION_DENY_SIGN = "io.github.moses70.pixelsshagent.action.DENY_SIGN"
        const val EXTRA_REQUEST_ID = "request_id"

        fun start(context: Context) {
            val intent = Intent(context, AgentForegroundService::class.java).setAction(ACTION_START)
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, AgentForegroundService::class.java).setAction(ACTION_STOP)
            context.startService(intent)
        }
    }
}
