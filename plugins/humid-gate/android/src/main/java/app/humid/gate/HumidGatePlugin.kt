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
//                 that is also biometric-only and authorised per use: its
//                 Cipher is bound to its own prompt (a second CryptoObject),
//                 so only a check HumID asked for can open it (LIVE-01). A
//                 BiometricPrompt CryptoObject holds one primitive, so a check
//                 that also signs with the liveness key is two prompts: the
//                 liveness key's, then the secret's (no confirm button). Only
//                 the ciphertext leaves the Keystore, inside the handle HumID
//                 stores with the identity.
//
//   handles v2    (2.0) the secret's key was usable for 3 s after ANY Class 3
//                 check, a lock-screen unlock included. Released once more the
//                 old way and moved to a v3 key in the same call; the new handle
//                 comes back as `handle`, and the old key is deleted the first
//                 time the v3 handle is used.
//
// Needs Android 11 (API 30) for biometric-only per-use keys.

package app.humid.gate

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.view.accessibility.AccessibilityManager
import android.os.Build
import android.os.Handler
import android.os.Looper
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
private const val HANDLE_VERSION = 3
/** 2.0 handles: the secret's key is time-bound (see the header). Migrated at their next release. */
private const val HANDLE_V2 = 2
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

private const val SUBTITLE = "HumID needs a live face or fingerprint"
/** The second prompt of a check that also signs with the liveness key. */
private const val SECRET_PROMPT = "Unlock your keys on this phone"
/** androidx.biometric needs a moment between one prompt closing and the next opening. */
private const val NEXT_PROMPT_DELAY_MS = 350L

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
    /** 2.0's time-bound secret key (handle v2): only read to migrate, then deleted. */
    private fun secretAlias(id: String) = "humid-gate-" + safe(id)
    /** The per-use secret key (handle v3), bound to its own prompt. */
    private fun secretKeyAlias(id: String) = "humid-secret-" + safe(id)
    private fun liveAlias(id: String) = "humid-live-" + safe(id)
    private fun keyStore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }
    private val main = Handler(Looper.getMainLooper())

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

    /**
     * The accessibility services switched on right now (APP-09, R15). An enabled service can read
     * every word in HumID's WebView and tap its buttons; FLAG_SECURE and the overlay rules don't
     * stop it. The app asks before it shows a document, a card or messages, and warns by name.
     * Returns `{ services: [{ id, label, canRead, canAct }] }`; `id` is the component name,
     * `label` what Settings > Accessibility calls it. `canRead`: it asked to retrieve window
     * content; `canAct`: it can perform gestures. Nothing is stored or sent anywhere.
     */
    @Command
    fun enabledAccessibilityServices(invoke: Invoke) {
        val list = JSArray()
        try {
            val am = activity.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
            val pm = activity.packageManager
            for (info in am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)) {
                val si = info.resolveInfo?.serviceInfo ?: continue
                val o = JSObject()
                o.put("id", "${si.packageName}/${si.name}".take(200))
                o.put("label", (si.loadLabel(pm)?.toString() ?: si.packageName).take(80))
                o.put("canRead", info.capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT != 0)
                o.put("canAct", info.capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES != 0)
                list.put(o)
            }
        } catch (e: Exception) {
            invoke.reject("Couldn't list accessibility services: ${e.message}")
            return
        }
        val out = JSObject()
        out.put("services", list)
        invoke.resolve(out)
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
        val (enc, live) = try {
            val key = createSecretKey(secretKeyAlias(id))
            Pair(Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key) }, prepareLive(id, args.challenge, args.attest))
        } catch (e: Exception) {
            remove(id)
            invoke.reject("Could not create the biometric key: ${e.message}")
            return
        }
        val title = args.prompt ?: "Bind HumID to your face or fingerprint"
        val secret = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val fail = { remove(id); secret.fill(0) }
        liveCheck(title, live, invoke, fail) { liveOut ->
            secretCheck(if (live == null) title else SECRET_PROMPT, live != null, enc, invoke, fail) { c ->
                try {
                    val ct = c.doFinal(secret)
                    val out = result(secret, liveOut)
                    out.put("handle", handle(id, c.iv, ct))
                    out
                } finally {
                    secret.fill(0)
                }
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
        val title = args.prompt ?: "Confirm it's you"
        when (h.v) {
            HANDLE_VERSION -> releaseV3(h.id, unb64(iv), unb64(ct), title, args, invoke)
            HANDLE_V2 -> migrateV2(h.id, unb64(iv), unb64(ct), title, args, invoke)
            else -> invoke.reject(OLD_VERSION)
        }
    }

    /** The secret's own per-use key opens it, inside its own prompt; the liveness key signs in the one before. */
    private fun releaseV3(id: String, iv: ByteArray, ct: ByteArray, title: String, args: ReleaseArgs, invoke: Invoke) {
        val (dec, live) = try {
            val k = loadSecretKey(secretKeyAlias(id))
            if (k == null) { invoke.reject(INVALIDATED); return }
            // Initialised now, so a key Android invalidated (biometrics changed) is found
            // before the person has looked at the sensor. The prompt authorises this operation.
            Pair(Cipher.getInstance(TRANSFORM).apply { init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(128, iv)) }, prepareLive(id, args.challenge, args.attest))
        } catch (e: KeyPermanentlyInvalidatedException) {
            invoke.reject(INVALIDATED); return
        } catch (e: Exception) {
            invoke.reject("Biometric key error: ${e.message}"); return
        }
        // This handle is the one in use now: a 2.0 time-bound key left by the migration goes.
        try { keyStore().deleteEntry(secretAlias(id)) } catch (_: Exception) {}
        liveCheck(title, live, invoke, {}) { liveOut ->
            secretCheck(if (live == null) title else SECRET_PROMPT, live != null, dec, invoke, {}) { c ->
                val secret = c.doFinal(ct)
                try { result(secret, liveOut) } finally { secret.fill(0) }
            }
        }
    }

    /**
     * A 2.0 handle: open the secret with its time-bound key one last time (inside the 3 s a
     * check HumID asked for has just opened), and seal it again under a new per-use key in
     * the same call. The new handle is returned as `handle`; the old key stays until that
     * handle is first used (releaseV3), so a caller that doesn't keep it loses nothing.
     */
    private fun migrateV2(id: String, iv: ByteArray, ct: ByteArray, title: String, args: ReleaseArgs, invoke: Invoke) {
        val (old, enc, live) = try {
            val k = loadSecretKey(secretAlias(id))
            if (k == null) { invoke.reject(INVALIDATED); return }
            try { Cipher.getInstance(TRANSFORM).init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(128, iv)) }
            catch (_: UserNotAuthenticatedException) { /* expected: it opens only after the check */ }
            val key = createSecretKey(secretKeyAlias(id)) // replaces one an earlier, unfinished migration made
            Triple(k, Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key) }, prepareLive(id, args.challenge, args.attest))
        } catch (e: KeyPermanentlyInvalidatedException) {
            invoke.reject(INVALIDATED); return
        } catch (e: Exception) {
            invoke.reject("Biometric key error: ${e.message}"); return
        }
        var secret: ByteArray? = null
        val openOld = { secret = Cipher.getInstance(TRANSFORM).apply { init(Cipher.DECRYPT_MODE, old, GCMParameterSpec(128, iv)) }.doFinal(ct) }
        val fail = { secret?.fill(0); Unit }
        liveCheck(title, live, invoke, fail) { liveOut ->
            if (live != null) openOld() // right after the liveness key's prompt, inside its 3 s
            secretCheck(if (live == null) title else SECRET_PROMPT, live != null, enc, invoke, fail) { c ->
                if (live == null) openOld() // the new key's prompt opened the old key's window too
                val s = secret ?: throw IllegalStateException("The secret couldn't be opened.")
                try {
                    val out = result(s, liveOut)
                    out.put("handle", handle(id, c.iv, c.doFinal(s)))
                    out
                } finally {
                    s.fill(0)
                }
            }
        }
    }

    private fun handle(id: String, iv: ByteArray, ct: ByteArray): JSObject {
        val h = JSObject()
        h.put("id", id)
        h.put("v", HANDLE_VERSION)
        h.put("iv", b64(iv))
        h.put("ct", b64(ct))
        return h
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
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG) // per use: only its own prompt opens it
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
            ks.deleteEntry(secretKeyAlias(id))
            ks.deleteEntry(liveAlias(id))
        } catch (_: Exception) {}
    }

    /** The response: the secret, and the liveness part when the check signed one. */
    private fun result(secret: ByteArray, live: JSObject?): JSObject {
        val out = JSObject()
        out.put("secret", b64(secret))
        out.put("method", METHOD)
        out.put("assurance", "hardware")
        val detail = JSObject()
        detail.put("factor", "biometric")
        out.put("detail", detail)
        if (live != null) out.put("live", live)
        return out
    }

    /** The liveness key's public key and signature (plus its attestation chain for a new key). */
    private fun liveJson(live: LivePrep, sig: ByteArray): JSObject {
        val l = JSObject()
        l.put("pub", b64(live.pub))
        l.put("sig", b64(sig))
        val chain = live.chain
        if (chain != null) {
            val a = JSObject()
            a.put("kind", "android-key")
            a.put("chain", chain)
            l.put("attestation", a)
        }
        return l
    }

    // ---------------- the prompts ----------------

    /**
     * The liveness key's prompt, when this check signs: the prompt unlocks its Signature
     * (CryptoObject), which signs the challenge at once, inside the callback. With no
     * liveness key (a device still waiting to join), next(null) straight away.
     */
    private fun liveCheck(title: String, live: LivePrep?, invoke: Invoke, onFail: () -> Unit, next: (JSObject?) -> Unit) {
        if (live == null) { next(null); return }
        authenticate(title, BiometricPrompt.CryptoObject(live.signature), confirm = true, invoke = invoke, onFail = onFail) { co ->
            val s = co?.signature ?: throw IllegalStateException("The biometric prompt returned no key.")
            s.update(live.challenge)
            next(liveJson(live, s.sign()))
        }
    }

    /**
     * The secret's prompt: it authorises exactly this Cipher operation (CryptoObject), so the
     * secret opens only inside a check HumID asked for, never in a window another unlock
     * opened. After the liveness prompt it opens a moment later, without a confirm button.
     */
    private fun secretCheck(title: String, second: Boolean, cipher: Cipher, invoke: Invoke, onFail: () -> Unit, onAuth: (Cipher) -> JSObject) {
        val go = {
            authenticate(title, BiometricPrompt.CryptoObject(cipher), confirm = !second, invoke = invoke, onFail = onFail) { co ->
                val c = co?.cipher ?: throw IllegalStateException("The biometric prompt returned no key.")
                invoke.resolve(onAuth(c))
            }
        }
        if (second) main.postDelayed({ go() }, NEXT_PROMPT_DELAY_MS) else go()
    }

    /**
     * Show the system biometric prompt (Class 3 only, no PIN / pattern / password option),
     * bound to `crypto`: onAuth receives it unlocked. A throw from onAuth is a refusal.
     */
    private fun authenticate(
        title: String,
        crypto: BiometricPrompt.CryptoObject,
        confirm: Boolean,
        invoke: Invoke,
        onFail: () -> Unit,
        onAuth: (BiometricPrompt.CryptoObject?) -> Unit,
    ) {
        val fa = activity as? FragmentActivity
        if (fa == null) { onFail(); invoke.reject("The app window cannot show a biometric prompt."); return }
        fa.runOnUiThread {
            val bp = BiometricPrompt(fa, ContextCompat.getMainExecutor(fa), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (result.authenticationType == BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL) {
                        onFail(); invoke.reject("HumID accepts only a live face or fingerprint."); return
                    }
                    try { onAuth(result.cryptoObject) }
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
                .setSubtitle(SUBTITLE)
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setConfirmationRequired(confirm)
                .build()
            bp.authenticate(info, crypto)
        }
    }

    companion object {
        const val INVALIDATED = "The device biometric key is gone or was invalidated by a biometric change. This identity can no longer be unlocked here."
        const val OLD_VERSION = "This device was set up by an earlier HumID version. Set HumID up again on this phone."
    }
}
