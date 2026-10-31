package app.voidwire.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import uniffi.voidwire_core.StateStorage

/** The phone's state blob (keys, pairings): reset when its format changes. */
const val STATE_FILE = "phone-state.bin"

/** The user's settings: versioned, migrated forward, never reset. */
const val SETTINGS_FILE = "phone-settings.bin"

/**
 * The phone's state blob (identity keys, paired PCs, group logs) on disk,
 * sealed with an AES-256-GCM key that never leaves the AndroidKeyStore.
 * The file lives in app-private storage and is excluded from backups
 * (allowBackup=false, data_extraction_rules.xml).
 *
 * The user's settings (relays, relay URL, file cap, mailbox, name) are a
 * second, separate blob, [SETTINGS_FILE], sealed the same way: a reset of
 * the state blob never touches them.
 *
 * File: "VW1" | iv (12) | ciphertext+tag. Written with AtomicFile.
 */
class KeystoreStateStorage(context: Context, name: String = STATE_FILE) : StateStorage {
    private val file = AtomicFile(File(context.noBackupFilesDir, name))

    override fun load(): ByteArray? {
        val raw = try {
            file.readFully()
        } catch (e: java.io.FileNotFoundException) {
            return null
        }
        return try {
            require(raw.size > MAGIC.size + IV_LEN && raw.copyOfRange(0, MAGIC.size).contentEquals(MAGIC))
            val iv = raw.copyOfRange(MAGIC.size, MAGIC.size + IV_LEN)
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
            cipher.updateAAD(MAGIC)
            cipher.doFinal(raw, MAGIC.size + IV_LEN, raw.size - MAGIC.size - IV_LEN)
        } catch (e: Exception) {
            // Unreadable (keystore key gone, e.g. after a device transfer):
            // nothing can ever open it again, so delete it (M1.1 privacy:
            // keep nothing we can't use) and start as a new, unpaired phone.
            file.delete()
            File(file.baseFile.path + ".unreadable").delete()
            null
        }
    }

    override fun save(data: ByteArray): Boolean = try {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(MAGIC)
        val ct = cipher.doFinal(data)
        val out = file.startWrite()
        try {
            out.write(MAGIC)
            out.write(cipher.iv)
            out.write(ct)
            file.finishWrite(out)
        } catch (e: Exception) {
            file.failWrite(out)
            throw e
        }
        true
    } catch (e: Exception) {
        false
    }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    private companion object {
        const val ALIAS = "voidwire-state-v1"
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val IV_LEN = 12
        val MAGIC = "VW1".toByteArray()
    }
}
