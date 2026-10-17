// Android gate (humid-gate@2). Every check is a live Class 3 (BIOMETRIC_STRONG)
// fingerprint or face match: the screen-lock PIN, pattern or password is never
// offered and never accepted.
//
//   liveness key  EC P-256 in the Android Keystore (StrongBox when present),
//                 biometric-only, authorised per use, invalidated when
//                 biometrics change. The prompt is bound to its Signature
//                 (CryptoObject), so it signs the request's challenge only
//                 inside this check. When a device is added (`attest` sent) a
//                 new key is made with that attestation challenge and its
//                 certificate chain goes to the server, which checks it
//                 against Google's roots and the key's properties.
//   secret        32 random bytes encrypted under an AES-256-GCM Keystore key
//                 that is also biometric-only and usable for a few seconds
//                 after the same check. Only the ciphertext leaves the
//                 Keystore, inside the handle HumID stores with the identity.
//
// Needs Android 11 (API 30) for biometric-only time-bound keys.

package app.humid.gate

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import android.view.WindowManager
import android.webkit.WebView
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
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
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val METHOD = "android-keystore-biometric"
private const val KEYSTORE = "AndroidKeyStore"
private const val TRANSFORM = "AES/GCM/NoPadding"
private const val HANDLE_VERSION = 2
/** Arguments come from the WebView: checked here, never trusted. */
private const val MAX_PROMPT = 120
private const val MAX_B64 = 8192
private val B64_RE = Regex("^[A-Za-z0-9+/]*={0,2}$")
private fun b64ok(s: String?, max: Int) = s == null || (s.length <= max && B64_RE.matches(s))
private fun badArgs(prompt: String?, challenge: String?, attest: String?): String? = when {
    prompt != null && (prompt.length > MAX_PROMPT || prompt.any { it.isISOControl() }) -> "The prompt isn't valid."
    !b64ok(challenge, MAX_B64) -> "The challenge isn't valid."
    !b64ok(attest, 128) -> "The attestation challenge isn't valid."
    else -> null
}

/** Seconds the secret's key stays usable after the live check. Biometric-only. */
private const val SECRET_WINDOW_S = 3

@InvokeArg
class EnrollArgs {
    var prompt: String? = null
    var challenge: String? = null
    var attest: String? = null
}

@InvokeArg
class HandleArg {
    lateinit var id: String
    var v: Int? = null
    var iv: String? = null
    var ct: String? = null
}

@InvokeArg
class ReleaseArgs {
    lateinit var handle: HandleArg
    var prompt: String? = null
    var challenge: String? = null
    var attest: String? = null
}

@InvokeArg
class ForgetArgs {
    lateinit var handle: HandleArg
}

@TauriPlugin
class HumidGatePlugin(private val activity: Activity) : Plugin(activity) {

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    private fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)
    private fun safe(id: String) = id.replace(Regex("[^A-Za-z0-9]"), "_")
    private fun secretAlias(id: String) = "humid-gate-" + safe(id)
    private fun liveAlias(id: String) = "humid-live-" + safe(id)
    private fun keyStore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    /**
     * Screen exposure, for the whole app (every screen shows something private: the vault,
     * codes, QR codes, the chip details form, the document camera):
     *   FLAG_SECURE          no screenshots, screen recording, casting or recents thumbnail
     *   hide overlays        other apps' windows (API 31+) can't draw over HumID
     *   no recents snapshot  API 33+, on top of FLAG_SECURE
     *   obscured touches     a tap that arrives through another app's window is dropped,
     *                        so an overlay can't steer a person into tapping Approve
     */
    override fun load(webView: WebView) {
        super.load(webView)
        activity.runOnUiThread {
            val w = activity.window
            w.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            if (Build.VERSION.SDK_INT >= 31) w.setHideOverlayWindows(true)
            if (Build.VERSION.SDK_INT >= 33) activity.setRecentsScreenshotEnabled(false)
            webView.filterTouchesWhenObscured = true
        }
    }

    @Command
    fun probe(invoke: Invoke) {
        val res = BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG)
        val pm = activity.packageManager
        val modalities = JSArray()
        if (pm.hasSystemFeature(PackageManager.FEATURE_FACE)) modalities.put("face")
        if (pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) modalities.put("fingerprint")
        val out = JSObject()
        out.put("available", res == BiometricManager.BIOMETRIC_SUCCESS)
        out.put("method", METHOD)
        out.put("assurance", "hardware")
        out.put("label", "your face or fingerprint")
        out.put("modalities", modalities)
        out.put("proof", "android-key")
        when (res) {
            BiometricManager.BIOMETRIC_SUCCESS -> {}
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                out.put("reason", "No strong fingerprint or face is enrolled. Add one in Settings > Security. A screen-lock PIN alone isn't accepted.")
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE, BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                out.put("reason", "This phone has no strong (Class 3) fingerprint or face sensor HumID can use.")
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
                out.put("reason", "Install the latest security update to use the biometric sensor with HumID.")
            else -> out.put("reason", "Biometric authentication is unavailable (code $res).")
        }
        invoke.resolve(out)
    }

    @Command
    fun enroll(invoke: Invoke) {
        val args = invoke.parseArgs(EnrollArgs::class.java)
        badArgs(args.prompt, args.challenge, args.attest)?.let { invoke.reject(it); return }
        val id = b64(ByteArray(16).also { SecureRandom().nextBytes(it) })
        val (secretKey, live) = try {
            Pair(createSecretKey(secretAlias(id)), prepareLive(id, args.challenge, args.attest))
        } catch (e: Exception) {
            remove(id)
            invoke.reject("Could not create the biometric key: ${e.message}")
            return
        }
        prompt(args.prompt ?: "Bind HumID to your face or fingerprint", live?.signature, invoke, onFail = { remove(id) }) { sig ->
            val secret = ByteArray(32).also { SecureRandom().nextBytes(it) }
            try {
                val c = Cipher.getInstance(TRANSFORM)
                c.init(Cipher.ENCRYPT_MODE, secretKey)
                val ct = c.doFinal(secret)
                val handle = JSObject()
                handle.put("id", id)
                handle.put("v", HANDLE_VERSION)
                handle.put("iv", b64(c.iv))
                handle.put("ct", b64(ct))
                val out = result(secret, live, sig)
                out.put("handle", handle)
                out
            } finally {
                secret.fill(0)
            }
        }
    }

    @Command
    fun release(invoke: Invoke) {
        val args = invoke.parseArgs(ReleaseArgs::class.java)
        badArgs(args.prompt, args.challenge, args.attest)?.let { invoke.reject(it); return }
        val h = args.handle
        val iv = h.iv
        val ct = h.ct
        if (iv == null || ct == null || !b64ok(h.id, 64) || !b64ok(iv, 64) || !b64ok(ct, 256)) { invoke.reject("The stored gate handle is malformed."); return }
        if (h.v != HANDLE_VERSION) { invoke.reject(OLD_VERSION); return }
        val (secretKey, live) = try {
            val k = loadSecretKey(secretAlias(h.id))
            if (k == null) { invoke.reject(INVALIDATED); return }
            // Find out now, not after the person has looked at the sensor, whether
            // Android has invalidated the key (biometrics changed since it was made).
            try { Cipher.getInstance(TRANSFORM).init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(128, unb64(iv))) }
            catch (_: UserNotAuthenticatedException) { /* expected: it opens only after the check */ }
            Pair(k, prepareLive(h.id, args.challenge, args.attest))
        } catch (e: KeyPermanentlyInvalidatedException) {
            invoke.reject(INVALIDATED); return
        } catch (e: Exception) {
            invoke.reject("Biometric key error: ${e.message}"); return
        }
        prompt(args.prompt ?: "Confirm it's you", live?.signature, invoke) { sig ->
            val c = Cipher.getInstance(TRANSFORM)
            c.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, unb64(iv)))
            val secret = c.doFinal(unb64(ct))
            try { result(secret, live, sig) } finally { secret.fill(0) }
        }
    }

    @Command
    fun forget(invoke: Invoke) {
        val args = invoke.parseArgs(ForgetArgs::class.java)
        if (!b64ok(args.handle.id, 64)) { invoke.reject("The stored gate handle is malformed."); return }
        remove(args.handle.id)
        invoke.resolve()
    }

    // ---------------- liveness key ----------------

    /** The challenge to sign, the Signature the prompt unlocks, and (for a new key) its attestation chain. */
    private class LivePrep(val challenge: ByteArray, val signature: Signature, val pub: ByteArray, val chain: JSArray?)

    /**
     * attest present: make a new liveness key attested to it. challenge present:
     * get a Signature ready for the prompt to unlock. Neither: no liveness key.
     */
    private fun prepareLive(id: String, challenge: String?, attest: String?): LivePrep? {
        val alias = liveAlias(id)
        var chain: JSArray? = null
        if (attest != null) {
            createLiveKey(alias, unb64(attest))
            val certs = keyStore().getCertificateChain(alias) ?: throw IllegalStateException("the new liveness key has no attestation")
            val arr = JSArray()
            for (cert in certs) arr.put(b64(cert.encoded))
            chain = arr
        }
        if (challenge == null) {
            if (attest != null) throw IllegalStateException("nothing for the new key to sign")
            return null
        }
        val ks = keyStore()
        val key = ks.getKey(alias, null) as PrivateKey?
        if (key == null) {
            if (attest != null) throw IllegalStateException("the new liveness key is missing")
            return null // a device still waiting to join has no liveness key yet
        }
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(key)
        return LivePrep(unb64(challenge), sig, ks.getCertificate(alias).publicKey.encoded, chain)
    }

    private fun createLiveKey(alias: String, attestationChallenge: ByteArray) {
        keyStore().deleteEntry(alias)
        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG) // per use, biometric only
                .setInvalidatedByBiometricEnrollment(true)
                .setUnlockedDeviceRequired(true) // never while the phone is locked
                .setAttestationChallenge(attestationChallenge)
            if (strongBox) b.setIsStrongBoxBacked(true)
            return b.build()
        }
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
        try {
            gen.initialize(spec(strongBox = true))
            gen.generateKeyPair()
            return
        } catch (_: Exception) {
            // No StrongBox secure element; use the TEE-backed Keystore.
        }
        gen.initialize(spec(strongBox = false))
        gen.generateKeyPair()
    }

    // ---------------- the secret ----------------

    private fun createSecretKey(alias: String): SecretKey {
        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(SECRET_WINDOW_S, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
                .setUnlockedDeviceRequired(true)
            if (strongBox) b.setIsStrongBoxBacked(true)
            return b.build()
        }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        try {
            gen.init(spec(strongBox = true))
            return gen.generateKey()
        } catch (_: Exception) {
            // No StrongBox secure element; use the TEE-backed Keystore.
        }
        gen.init(spec(strongBox = false))
        return gen.generateKey()
    }

    private fun loadSecretKey(alias: String): SecretKey? = keyStore().getKey(alias, null) as SecretKey?

    private fun remove(id: String) {
        try {
            val ks = keyStore()
            ks.deleteEntry(secretAlias(id))
            ks.deleteEntry(liveAlias(id))
        } catch (_: Exception) {}
    }

    /** The response: secret, and the liveness signature (plus attestation for a new key). */
    private fun result(secret: ByteArray, live: LivePrep?, sig: Signature?): JSObject {
        val out = JSObject()
        out.put("secret", b64(secret))
        out.put("method", METHOD)
        out.put("assurance", "hardware")
        val detail = JSObject()
        detail.put("factor", "biometric")
        out.put("detail", detail)
        if (live != null && sig != null) {
            sig.update(live.challenge)
            val l = JSObject()
            l.put("pub", b64(live.pub))
            l.put("sig", b64(sig.sign()))
            val chain = live.chain
            if (chain != null) {
                val a = JSObject()
                a.put("kind", "android-key")
                a.put("chain", chain)
                l.put("attestation", a)
            }
            out.put("live", l)
        }
        return out
    }

    // ---------------- the prompt ----------------

    /**
     * Show the system biometric prompt (Class 3 only, no PIN / pattern /
     * password option). With a Signature, the prompt is bound to it and
     * onAuth receives it unlocked; without, onAuth gets null.
     */
    private fun prompt(
        title: String,
        signature: Signature?,
        invoke: Invoke,
        onFail: () -> Unit = {},
        onAuth: (Signature?) -> JSObject,
    ) {
        val fa = activity as? FragmentActivity
        if (fa == null) { onFail(); invoke.reject("The app window cannot show a biometric prompt."); return }
        fa.runOnUiThread {
            val bp = BiometricPrompt(fa, ContextCompat.getMainExecutor(fa), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (result.authenticationType == BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL) {
                        onFail(); invoke.reject("HumID accepts only a live face or fingerprint."); return
                    }
                    val s = result.cryptoObject?.signature
                    if (signature != null && s == null) { onFail(); invoke.reject("The biometric prompt returned no key."); return }
                    try { invoke.resolve(onAuth(s)) }
                    catch (e: KeyPermanentlyInvalidatedException) { onFail(); invoke.reject(INVALIDATED) }
                    catch (e: Exception) { onFail(); invoke.reject("Biometric key error: ${e.message}") }
                }
                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    onFail()
                    when (code) {
                        BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_CANCELED, BiometricPrompt.ERROR_TIMEOUT ->
                            invoke.reject("Biometric check cancelled.")
                        BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT ->
                            invoke.reject("Too many tries. Unlock your phone, then try again with your face or fingerprint.")
                        else -> invoke.reject(msg.toString())
                    }
                }
                // onAuthenticationFailed = one non-matching attempt; the prompt stays up.
            })
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle("HumID needs a live face or fingerprint")
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setConfirmationRequired(true)
                .build()
            if (signature != null) bp.authenticate(info, BiometricPrompt.CryptoObject(signature))
            else bp.authenticate(info)
        }
    }

    companion object {
        const val INVALIDATED = "The device biometric key is gone or was invalidated by a biometric change. This identity can no longer be unlocked here."
        const val OLD_VERSION = "This device was set up by an earlier HumID version. Set HumID up again on this phone."
    }
}
