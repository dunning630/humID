// Android gate: an AES-256-GCM key in the Android Keystore (StrongBox when
// the device has it) that requires a BIOMETRIC_STRONG match for every use and
// is invalidated if fingerprints/faces are added. A random 32-byte secret is
// encrypted under it; only the ciphertext leaves the Keystore, inside the
// handle that HumID stores with the identity.

package app.humid.gate

import android.app.Activity
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val METHOD = "android-keystore-biometric"
private const val KEYSTORE = "AndroidKeyStore"
private const val TRANSFORM = "AES/GCM/NoPadding"

@InvokeArg
class EnrollArgs {
    var prompt: String? = null
}

@InvokeArg
class HandleArg {
    lateinit var id: String
    var iv: String? = null
    var ct: String? = null
}

@InvokeArg
class ReleaseArgs {
    lateinit var handle: HandleArg
    var prompt: String? = null
}

@InvokeArg
class ForgetArgs {
    lateinit var handle: HandleArg
}

@TauriPlugin
class HumidGatePlugin(private val activity: Activity) : Plugin(activity) {

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    private fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)
    private fun alias(id: String) = "humid-gate-" + id.replace(Regex("[^A-Za-z0-9]"), "_")

    @Command
    fun probe(invoke: Invoke) {
        val res = BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG)
        val out = JSObject()
        out.put("available", res == BiometricManager.BIOMETRIC_SUCCESS)
        out.put("method", METHOD)
        out.put("assurance", "hardware")
        out.put("label", "Device biometric (Class 3)")
        when (res) {
            BiometricManager.BIOMETRIC_SUCCESS -> {}
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                out.put("reason", "No fingerprint or face is enrolled. Add one in Settings > Security.")
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE, BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                out.put("reason", "This device has no strong (Class 3) biometric sensor available.")
            else -> out.put("reason", "Biometric authentication is unavailable (code $res).")
        }
        invoke.resolve(out)
    }

    @Command
    fun enroll(invoke: Invoke) {
        val args = invoke.parseArgs(EnrollArgs::class.java)
        val idBytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val id = b64(idBytes)
        try {
            val key = createKey(alias(id))
            val cipher = Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key) }
            prompt(args.prompt ?: "Bind your HumID identity to this device", cipher, invoke) { c ->
                val secret = ByteArray(32).also { SecureRandom().nextBytes(it) }
                val ct = c.doFinal(secret)
                val handle = JSObject()
                handle.put("id", id)
                handle.put("iv", b64(c.iv))
                handle.put("ct", b64(ct))
                val out = JSObject()
                out.put("handle", handle)
                out.put("secret", b64(secret))
                out.put("method", METHOD)
                out.put("assurance", "hardware")
                out.put("detail", JSObject().put("factor", "biometric"))
                secret.fill(0)
                out
            }
        } catch (e: Exception) {
            invoke.reject("Could not create the biometric key: ${e.message}")
        }
    }

    @Command
    fun release(invoke: Invoke) {
        val args = invoke.parseArgs(ReleaseArgs::class.java)
        val h = args.handle
        val iv = h.iv; val ct = h.ct
        if (iv == null || ct == null) { invoke.reject("The stored gate handle is malformed."); return }
        val cipher: Cipher
        try {
            val key = loadKey(alias(h.id)) ?: run { invoke.reject(INVALIDATED); return }
            cipher = Cipher.getInstance(TRANSFORM).apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, unb64(iv))) }
        } catch (e: KeyPermanentlyInvalidatedException) {
            invoke.reject(INVALIDATED); return
        } catch (e: Exception) {
            invoke.reject("Biometric key error: ${e.message}"); return
        }
        prompt(args.prompt ?: "Confirm it's you", cipher, invoke) { c ->
            val secret = c.doFinal(unb64(ct))
            val out = JSObject()
            out.put("secret", b64(secret))
            out.put("method", METHOD)
            out.put("assurance", "hardware")
            out.put("detail", JSObject().put("factor", "biometric"))
            secret.fill(0)
            out
        }
    }

    @Command
    fun forget(invoke: Invoke) {
        val args = invoke.parseArgs(ForgetArgs::class.java)
        try {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(alias(args.handle.id))
        } catch (_: Exception) {}
        invoke.resolve()
    }

    private fun createKey(alias: String): SecretKey {
        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                b.setUserAuthenticationValidityDurationSeconds(-1) // auth per use
            }
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) b.setIsStrongBoxBacked(true)
            return b.build()
        }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                gen.init(spec(strongBox = true)); return gen.generateKey()
            } catch (_: Exception) {
                // No StrongBox secure element; fall back to the TEE-backed Keystore.
            }
        }
        gen.init(spec(strongBox = false))
        return gen.generateKey()
    }

    private fun loadKey(alias: String): SecretKey? =
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.getKey(alias, null) as SecretKey?

    private fun prompt(title: String, cipher: Cipher, invoke: Invoke, onAuth: (Cipher) -> JSObject) {
        val fa = activity as? FragmentActivity
        if (fa == null) { invoke.reject("The app window cannot show a biometric prompt."); return }
        fa.runOnUiThread {
            val bp = BiometricPrompt(fa, ContextCompat.getMainExecutor(fa), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val c = result.cryptoObject?.cipher
                    if (c == null) { invoke.reject("The biometric prompt returned no key."); return }
                    try { invoke.resolve(onAuth(c)) } catch (e: Exception) { invoke.reject("Biometric key error: ${e.message}") }
                }
                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    when (code) {
                        BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_CANCELED, BiometricPrompt.ERROR_TIMEOUT ->
                            invoke.reject("Biometric check cancelled.")
                        else -> invoke.reject(msg.toString())
                    }
                }
                // onAuthenticationFailed = one non-matching attempt; the prompt stays up.
            })
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle("HumID biological interrupt")
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .build()
            bp.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        }
    }

    companion object {
        const val INVALIDATED = "The device biometric key is gone or was invalidated by a biometric change. This identity can no longer be unlocked here."
    }
}
