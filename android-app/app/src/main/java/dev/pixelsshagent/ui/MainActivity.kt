package dev.pixelsshagent.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dev.pixelsshagent.crypto.ManagedKey
import dev.pixelsshagent.service.AgentCoordinator
import dev.pixelsshagent.service.AgentForegroundService
import dev.pixelsshagent.service.AgentLogEntry
import dev.pixelsshagent.service.AgentSettings
import dev.pixelsshagent.service.PendingSignRequest
import dev.pixelsshagent.ssh.SshKeyAlgorithm
import dev.pixelsshagent.tunnel.TunnelConnectionState

class MainActivity : FragmentActivity() {
    private lateinit var coordinator: AgentCoordinator
    private var activePromptRequestId: String? = null

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* optional notification permission */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        coordinator = AgentCoordinator.get(this)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        setContent {
            PixelSshAgentTheme {
                AgentAppScreen(
                    coordinator = coordinator,
                    onStartService = { AgentForegroundService.start(this) },
                    onStopService = { AgentForegroundService.stop(this) },
                    onTriggerBiometric = { request -> launchBiometricPrompt(request) },
                )
            }
        }
    }

    private fun launchBiometricPrompt(request: PendingSignRequest) {
        if (activePromptRequestId == request.requestId) return
        val bm = BiometricManager.from(this)
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        if (bm.canAuthenticate(authenticators) != BiometricManager.BIOMETRIC_SUCCESS) {
            // Device has no biometrics/PIN configured (e.g. fresh emulator); user can approve via dialog card.
            return
        }

        activePromptRequestId = request.requestId
        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    activePromptRequestId = null
                    coordinator.resolvePendingSign(request.requestId, approved = true)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    activePromptRequestId = null
                    coordinator.resolvePendingSign(request.requestId, approved = false)
                }
            },
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Approve SSH Signature")
            .setSubtitle("${request.keyComment} (${request.algorithm.sshName})")
            .setDescription("Fingerprint: ${request.fingerprint}")
            .setAllowedAuthenticators(authenticators)
            .build()

        prompt.authenticate(promptInfo)
    }
}

@Composable
private fun PixelSshAgentTheme(content: @Composable () -> Unit) {
    val context = LocalContext.current
    val dark = androidx.compose.foundation.isSystemInDarkTheme()
    val scheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && dark -> dynamicDarkColorScheme(context)
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && !dark -> dynamicLightColorScheme(context)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AgentAppScreen(
    coordinator: AgentCoordinator,
    onStartService: () -> Unit,
    onStopService: () -> Unit,
    onTriggerBiometric: (PendingSignRequest) -> Unit,
) {
    var selectedTab by remember { mutableIntStateOf(0) }
    var showCreateKeyDialog by remember { mutableStateOf(false) }

    val settings by coordinator.settings.collectAsState()
    val keys by coordinator.keys.collectAsState()
    val connectionState by coordinator.connectionState.collectAsState()
    val statusMessage by coordinator.statusMessage.collectAsState()
    val logs by coordinator.logs.collectAsState()
    val pendingSign by coordinator.pendingSignRequest.collectAsState()

    LaunchedEffect(pendingSign?.requestId) {
        pendingSign?.let { onTriggerBiometric(it) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Pixel SSH Agent", fontWeight = FontWeight.SemiBold) },
                actions = {
                    if (settings.unlockWindowMinutes > 0) {
                        IconButton(onClick = { coordinator.lockNow() }) {
                            Icon(Icons.Default.Lock, contentDescription = "Lock now")
                        }
                    }
                },
            )
        },
        floatingActionButton = {
            if (selectedTab == 1) {
                FloatingActionButton(onClick = { showCreateKeyDialog = true }) {
                    Icon(Icons.Default.Add, contentDescription = "Generate SSH key")
                }
            }
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = { Icon(Icons.Default.Link, contentDescription = null) },
                    label = { Text("Tunnel") },
                )
                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    icon = { Icon(Icons.Default.Key, contentDescription = null) },
                    label = { Text("Keys (${keys.size})") },
                )
                NavigationBarItem(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    icon = { Icon(Icons.AutoMirrored.Filled.List, contentDescription = null) },
                    label = { Text("Log") },
                )
            }
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
        ) {
            pendingSign?.let { req ->
                PendingApprovalBanner(
                    request = req,
                    onApprove = { coordinator.resolvePendingSign(req.requestId, true) },
                    onDeny = { coordinator.resolvePendingSign(req.requestId, false) },
                )
            }

            when (selectedTab) {
                0 -> TunnelAndPairingTab(
                    settings = settings,
                    connectionState = connectionState,
                    statusMessage = statusMessage,
                    onSaveSettings = { coordinator.updateSettings(it) },
                    onRegeneratePsk = { coordinator.regeneratePsk() },
                    onStartService = onStartService,
                    onStopService = onStopService,
                )

                1 -> KeysTab(
                    keys = keys,
                    onDeleteKey = { coordinator.deleteKey(it) },
                )

                2 -> ActivityLogTab(logs = logs)
            }
        }
    }

    if (showCreateKeyDialog) {
        CreateKeyDialog(
            onDismiss = { showCreateKeyDialog = false },
            onCreate = { comment, algo, requireBio ->
                coordinator.createKey(comment, algo, requireBio)
                showCreateKeyDialog = false
            },
        )
    }
}

@Composable
private fun PendingApprovalBanner(
    request: PendingSignRequest,
    onApprove: () -> Unit,
    onDeny: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Fingerprint, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(
                    "SSH Sign Request: ${request.keyComment}",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(
                "${request.algorithm.sshName} • ${request.payloadBytes} bytes",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                request.fingerprint,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onApprove) { Text("Approve") }
                OutlinedButton(onClick = onDeny) { Text("Deny") }
            }
        }
    }
}

@Composable
private fun TunnelAndPairingTab(
    settings: AgentSettings,
    connectionState: TunnelConnectionState,
    statusMessage: String?,
    onSaveSettings: (AgentSettings) -> Unit,
    onRegeneratePsk: () -> String,
    onStartService: () -> Unit,
    onStopService: () -> Unit,
) {
    val context = LocalContext.current
    var portText by remember(settings.port) { mutableStateOf(settings.port.toString()) }
    var pskText by remember(settings.pskHex) { mutableStateOf(settings.pskHex) }
    var unlockMinutes by remember(settings.unlockWindowMinutes) { mutableIntStateOf(settings.unlockWindowMinutes) }

    val running = connectionState != TunnelConnectionState.STOPPED
    val statusColor = when (connectionState) {
        TunnelConnectionState.CONNECTED -> Color(0xFF2E7D32)
        TunnelConnectionState.CONNECTING -> Color(0xFFEF6C00)
        TunnelConnectionState.AUTH_FAILED, TunnelConnectionState.ERROR -> Color(0xFFC62828)
        TunnelConnectionState.STOPPED -> Color.Gray
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .clip(CircleShape)
                            .background(statusColor),
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        text = when (connectionState) {
                            TunnelConnectionState.CONNECTED -> "Connected to Debian VM"
                            TunnelConnectionState.CONNECTING -> "Waiting for Debian Bridge..."
                            TunnelConnectionState.AUTH_FAILED -> "Authentication Failed"
                            TunnelConnectionState.ERROR -> "Connection Error"
                            TunnelConnectionState.STOPPED -> "Agent Service Stopped"
                        },
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
                if (!statusMessage.isNullOrBlank()) {
                    Text(statusMessage, style = MaterialTheme.typography.bodySmall)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(
                        onClick = { if (running) onStopService() else onStartService() },
                        colors = if (running) {
                            ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                        } else {
                            ButtonDefaults.buttonColors()
                        },
                    ) {
                        Icon(
                            if (running) Icons.Default.Stop else Icons.Default.PlayArrow,
                            contentDescription = null,
                        )
                        Spacer(Modifier.width(6.dp))
                        Text(if (running) "Stop Agent" else "Start Agent")
                    }
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("AVF Tunnel & Pairing (Option B)", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Allow port forwarding for this port in Pixel Linux Terminal settings. " +
                        "Android maps it strictly to 127.0.0.1.",
                    style = MaterialTheme.typography.bodySmall,
                )

                OutlinedTextField(
                    value = portText,
                    onValueChange = { portText = it.filter(Char::isDigit).take(5) },
                    label = { Text("AVF Forwarded Port (127.0.0.1)") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                OutlinedTextField(
                    value = pskText,
                    onValueChange = { pskText = it.trim().lowercase() },
                    label = { Text("Pairing PSK (64 hex chars / 256-bit)") },
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    maxLines = 2,
                    trailingIcon = {
                        IconButton(onClick = { pskText = onRegeneratePsk() }) {
                            Icon(Icons.Default.Refresh, contentDescription = "Regenerate PSK")
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                )

                Text("Biometric Unlock Window", style = MaterialTheme.typography.labelLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(0 to "Every sign", 1 to "1 min", 5 to "5 min", 15 to "15 min").forEach { (mins, label) ->
                        FilterChip(
                            selected = unlockMinutes == mins,
                            onClick = { unlockMinutes = mins },
                            label = { Text(label) },
                        )
                    }
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {
                            val parsedPort = portText.toIntOrNull() ?: settings.port
                            onSaveSettings(
                                settings.copy(
                                    port = parsedPort,
                                    pskHex = pskText,
                                    unlockWindowMinutes = unlockMinutes,
                                ),
                            )
                            Toast.makeText(context, "Settings saved", Toast.LENGTH_SHORT).show()
                        },
                    ) {
                        Text("Save")
                    }
                    OutlinedButton(
                        onClick = {
                            val parsedPort = portText.toIntOrNull() ?: settings.port
                            val cmd = "pixel-ssh-agent-bridge init --port $parsedPort --psk $pskText"
                            copyToClipboard(context, "Debian Bridge Init Command", cmd)
                        },
                    ) {
                        Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Copy Debian Init")
                    }
                }
            }
        }
    }
}

@Composable
private fun KeysTab(
    keys: List<ManagedKey>,
    onDeleteKey: (String) -> Unit,
) {
    val context = LocalContext.current
    if (keys.isEmpty()) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text(
                "No SSH keys yet.\nTap + to create a Hardware ECDSA P-256 or Ed25519 key.",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(24.dp),
            )
        }
        return
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(keys, key = { it.id }) { key ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(key.comment, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Row {
                            IconButton(
                                onClick = {
                                    copyToClipboard(context, "SSH Public Key", key.authorizedKeysLine())
                                },
                            ) {
                                Icon(Icons.Default.ContentCopy, contentDescription = "Copy authorized_keys")
                            }
                            IconButton(onClick = { onDeleteKey(key.id) }) {
                                Icon(Icons.Default.Delete, contentDescription = "Delete key")
                            }
                        }
                    }
                    val badge = buildString {
                        append(key.algorithm.sshName)
                        if (key.strongBoxBacked) append(" • StrongBox")
                        else if (key.algorithm == SshKeyAlgorithm.ECDSA_P256) append(" • AndroidKeyStore")
                        else append(" • Keystore-wrapped")
                        if (key.requireBiometric) append(" • Biometric")
                    }
                    Text(badge, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                    Text(
                        key.fingerprint,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
        }
    }
}

@Composable
private fun ActivityLogTab(logs: List<AgentLogEntry>) {
    if (logs.isEmpty()) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("No agent activity yet.")
        }
        return
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        items(logs) { entry ->
            Row(modifier = Modifier.fillMaxWidth()) {
                Text(
                    entry.timestamp,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.primary,
                )
                Spacer(Modifier.width(10.dp))
                Text(
                    entry.message,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }
}

@Composable
private fun CreateKeyDialog(
    onDismiss: () -> Unit,
    onCreate: (comment: String, algorithm: SshKeyAlgorithm, requireBiometric: Boolean) -> Unit,
) {
    var comment by remember { mutableStateOf("pixel@debian") }
    var algorithm by remember { mutableStateOf(SshKeyAlgorithm.ECDSA_P256) }
    var requireBio by remember { mutableStateOf(true) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Generate SSH Key") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = comment,
                    onValueChange = { comment = it },
                    label = { Text("Key Comment") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = algorithm == SshKeyAlgorithm.ECDSA_P256,
                        onClick = { algorithm = SshKeyAlgorithm.ECDSA_P256 },
                        label = { Text("ECDSA P-256 (HW)") },
                    )
                    FilterChip(
                        selected = algorithm == SshKeyAlgorithm.ED25519,
                        onClick = { algorithm = SshKeyAlgorithm.ED25519 },
                        label = { Text("Ed25519") },
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Require Biometric Confirmation")
                    Switch(checked = requireBio, onCheckedChange = { requireBio = it })
                }
            }
        },
        confirmButton = {
            Button(onClick = { onCreate(comment, algorithm, requireBio) }) {
                Text("Generate")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        },
    )
}

private fun copyToClipboard(context: Context, label: String, text: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText(label, text))
    Toast.makeText(context, "Copied: $label", Toast.LENGTH_SHORT).show()
}
