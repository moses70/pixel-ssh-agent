package dev.pixelsshagent.crypto

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import dev.pixelsshagent.ssh.SshKeyAlgorithm
import dev.pixelsshagent.ssh.SshPublicKey
import dev.pixelsshagent.ssh.SshSignature
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class ManagedKey(
    val id: String,
    val comment: String,
    val algorithm: SshKeyAlgorithm,
    val publicKey: SshPublicKey,
    val requireBiometric: Boolean,
    val strongBoxBacked: Boolean,
    val createdAtMs: Long,
    internal val keystoreAlias: String? = null,
    internal val wrappedSeedB64: String? = null,
) {
    val fingerprint: String
        get() = publicKey.sha256Fingerprint()

    fun authorizedKeysLine(): String = publicKey.toAuthorizedKeysLine(comment)
}

/**
 * Manages SSH keys on Android:
 * - ECDSA P-256 keys live directly inside AndroidKeyStore (StrongBox if available, TEE fallback).
 * - Ed25519 32-byte seeds are encrypted at rest with an AndroidKeyStore AES-256-GCM master key.
 */
class KeyRepository(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private val lock = Any()

    fun listKeys(): List<ManagedKey> = synchronized(lock) {
        loadAllLocked()
    }

    fun findByBlob(blob: ByteArray): ManagedKey? = synchronized(lock) {
        loadAllLocked().firstOrNull { it.publicKey.blob.contentEquals(blob) }
    }

    fun createKey(
        comment: String,
        algorithm: SshKeyAlgorithm,
        requireBiometric: Boolean = true,
    ): ManagedKey = synchronized(lock) {
        val cleanComment = comment.trim().ifEmpty { "pixel-${algorithm.sshName}" }
        val id = UUID.randomUUID().toString()
        val createdAt = System.currentTimeMillis()

        val entry = when (algorithm) {
            SshKeyAlgorithm.ECDSA_P256 -> createEcdsaKey(id, cleanComment, requireBiometric, createdAt)
            SshKeyAlgorithm.ED25519 -> createEd25519Key(id, cleanComment, requireBiometric, createdAt)
        }

        val current = loadAllLocked().toMutableList()
        current.add(entry)
        saveAllLocked(current)
        entry
    }

    fun deleteKey(id: String): Boolean = synchronized(lock) {
        val current = loadAllLocked().toMutableList()
        val target = current.firstOrNull { it.id == id } ?: return false
        current.remove(target)
        saveAllLocked(current)
        target.keystoreAlias?.let { alias ->
            runCatching {
                if (keyStore.containsAlias(alias)) {
                    keyStore.deleteEntry(alias)
                }
            }
        }
        true
    }

    fun sign(key: ManagedKey, data: ByteArray): ByteArray = synchronized(lock) {
        when (key.algorithm) {
            SshKeyAlgorithm.ECDSA_P256 -> {
                val alias = requireNotNull(key.keystoreAlias) { "Missing keystore alias" }
                val privateKey = keyStore.getKey(alias, null) as? PrivateKey
                    ?: throw IllegalStateException("Keystore entry not found: $alias")
                val signer = Signature.getInstance("SHA256withECDSA")
                signer.initSign(privateKey)
                signer.update(data)
                val derSig = signer.sign()
                SshSignature.encodeEcdsaP256FromDer(derSig)
            }

            SshKeyAlgorithm.ED25519 -> {
                val wrappedB64 = requireNotNull(key.wrappedSeedB64) { "Missing wrapped Ed25519 seed" }
                val seed = unwrapSeed(Base64.getDecoder().decode(wrappedB64))
                try {
                    val rawSig = Ed25519Pure.sign(seed, data)
                    SshSignature.encodeEd25519(rawSig)
                } finally {
                    seed.fill(0)
                }
            }
        }
    }

    private fun createEcdsaKey(
        id: String,
        comment: String,
        requireBiometric: Boolean,
        createdAt: Long,
    ): ManagedKey {
        val alias = "psa_ecdsa_$id"
        var strongBox = false
        val keyPair = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                strongBox = true
                generateAndroidKeystoreEc(alias, useStrongBox = true)
            } else {
                generateAndroidKeystoreEc(alias, useStrongBox = false)
            }
        } catch (_: StrongBoxUnavailableException) {
            strongBox = false
            generateAndroidKeystoreEc(alias, useStrongBox = false)
        } catch (_: Exception) {
            strongBox = false
            generateAndroidKeystoreEc(alias, useStrongBox = false)
        }

        val sshPub = SshPublicKey.fromEcdsaP256(keyPair.public as ECPublicKey)
        return ManagedKey(
            id = id,
            comment = comment,
            algorithm = SshKeyAlgorithm.ECDSA_P256,
            publicKey = sshPub,
            requireBiometric = requireBiometric,
            strongBoxBacked = strongBox,
            createdAtMs = createdAt,
            keystoreAlias = alias,
        )
    }

    private fun generateAndroidKeystoreEc(alias: String, useStrongBox: Boolean): java.security.KeyPair {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        kpg.initialize(builder.build())
        return kpg.generateKeyPair()
    }

    private fun createEd25519Key(
        id: String,
        comment: String,
        requireBiometric: Boolean,
        createdAt: Long,
    ): ManagedKey {
        val seed = Ed25519Pure.generateSeed()
        return try {
            val rawPub = Ed25519Pure.publicKeyFromSeed(seed)
            val sshPub = SshPublicKey.fromEd25519(rawPub)
            val wrapped = wrapSeed(seed)
            ManagedKey(
                id = id,
                comment = comment,
                algorithm = SshKeyAlgorithm.ED25519,
                publicKey = sshPub,
                requireBiometric = requireBiometric,
                strongBoxBacked = false,
                createdAtMs = createdAt,
                wrappedSeedB64 = Base64.getEncoder().encodeToString(wrapped),
            )
        } finally {
            seed.fill(0)
        }
    }

    private fun getOrCreateMasterAesKey(): SecretKey {
        val existing = keyStore.getKey(MASTER_AES_ALIAS, null) as? SecretKey
        if (existing != null) return existing

        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            MASTER_AES_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGen.init(spec)
        return keyGen.generateKey()
    }

    private fun wrapSeed(seed: ByteArray): ByteArray {
        val masterKey = getOrCreateMasterAesKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, masterKey)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(seed)
        val out = ByteArray(1 + iv.size + ciphertext.size)
        out[0] = iv.size.toByte()
        System.arraycopy(iv, 0, out, 1, iv.size)
        System.arraycopy(ciphertext, 0, out, 1 + iv.size, ciphertext.size)
        return out
    }

    private fun unwrapSeed(blob: ByteArray): ByteArray {
        require(blob.size > 13) { "Corrupted wrapped Ed25519 seed" }
        val ivLen = blob[0].toInt() and 0xFF
        val iv = blob.copyOfRange(1, 1 + ivLen)
        val ciphertext = blob.copyOfRange(1 + ivLen, blob.size)
        val masterKey = getOrCreateMasterAesKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(128, iv))
        return cipher.doFinal(ciphertext)
    }

    private fun loadAllLocked(): List<ManagedKey> {
        val raw = prefs.getString(KEY_LIST_JSON, null) ?: return emptyList()
        val arr = JSONArray(raw)
        val out = ArrayList<ManagedKey>(arr.length())
        for (i in 0 until arr.length()) {
            val obj = arr.getJSONObject(i)
            val algo = SshKeyAlgorithm.fromSshName(obj.getString("algorithm")) ?: continue
            val pubBlob = Base64.getDecoder().decode(obj.getString("pubBlob"))
            out.add(
                ManagedKey(
                    id = obj.getString("id"),
                    comment = obj.getString("comment"),
                    algorithm = algo,
                    publicKey = SshPublicKey(algo, pubBlob),
                    requireBiometric = obj.optBoolean("requireBiometric", true),
                    strongBoxBacked = obj.optBoolean("strongBoxBacked", false),
                    createdAtMs = obj.optLong("createdAtMs", 0L),
                    keystoreAlias = obj.optString("keystoreAlias", "").ifEmpty { null },
                    wrappedSeedB64 = obj.optString("wrappedSeedB64", "").ifEmpty { null },
                ),
            )
        }
        return out
    }

    private fun saveAllLocked(keys: List<ManagedKey>) {
        val arr = JSONArray()
        for (key in keys) {
            val obj = JSONObject()
            obj.put("id", key.id)
            obj.put("comment", key.comment)
            obj.put("algorithm", key.algorithm.sshName)
            obj.put("pubBlob", Base64.getEncoder().encodeToString(key.publicKey.blob))
            obj.put("requireBiometric", key.requireBiometric)
            obj.put("strongBoxBacked", key.strongBoxBacked)
            obj.put("createdAtMs", key.createdAtMs)
            key.keystoreAlias?.let { obj.put("keystoreAlias", it) }
            key.wrappedSeedB64?.let { obj.put("wrappedSeedB64", it) }
            arr.put(obj)
        }
        prefs.edit().putString(KEY_LIST_JSON, arr.toString()).apply()
    }

    companion object {
        private const val PREFS_NAME = "pixel_ssh_agent_keys"
        private const val KEY_LIST_JSON = "managed_keys_v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val MASTER_AES_ALIAS = "psa_ed25519_master_aes_v1"
    }
}
