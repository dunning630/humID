// Android chip reader (humid-nfc@1). NFC reader mode finds an ISO-DEP chip
// (ISO 14443 A or B): a passport or ID card, or a contactless payment card,
// and this plugin passes APDUs to and from it. All ICAO 9303 logic runs in the
// shared @humid/emrtd module, and the payment-card read in @humid/cards.

package app.humid.nfc

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Base64
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.util.UUID
import java.util.concurrent.Executors

@InvokeArg
class BeginArgs {
    var prompt: String? = null
    var timeoutMs: Long? = null
    var reader: String? = null
}

@InvokeArg
class TransceiveArgs {
    lateinit var session: String
    lateinit var apdu: String
}

@InvokeArg
class MessageArgs {
    lateinit var session: String
    lateinit var message: String
}

@InvokeArg
class EndArgs {
    lateinit var session: String
    var message: String? = null
    var error: String? = null
}

@TauriPlugin
class HumidNfcPlugin(private val activity: Activity) : Plugin(activity) {
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var isoDep: IsoDep? = null
    private var sessionId: String? = null
    private var waiting: Invoke? = null
    private var timeout: Runnable? = null

    private fun adapter(): NfcAdapter? = NfcAdapter.getDefaultAdapter(activity)

    @Command
    fun probe(invoke: Invoke) {
        val a = adapter()
        val out = JSObject()
        out.put("readers", JSArray())
        when {
            a == null -> { out.put("available", false); out.put("kind", "none"); out.put("reason", "This phone has no NFC, so it can't read ID chips.") }
            !a.isEnabled -> { out.put("available", false); out.put("kind", "phone"); out.put("reason", "Turn on NFC in Settings to read your passport or ID card chip.") }
            else -> { out.put("available", true); out.put("kind", "phone") }
        }
        invoke.resolve(out)
    }

    @Command
    fun begin(invoke: Invoke) {
        val args = invoke.parseArgs(BeginArgs::class.java)
        val a = adapter()
        if (a == null || !a.isEnabled) { invoke.reject(if (a == null) "This phone has no NFC." else "Turn on NFC in Settings, then try again."); return }
        waiting?.reject("Chip reading cancelled.")
        stop()
        waiting = invoke
        val flags = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS
        val extras = Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 1000) }
        main.post {
            a.enableReaderMode(activity, { tag -> onTag(tag) }, flags, extras)
        }
        val t = Runnable { waiting?.reject("Chip reading cancelled."); waiting = null; stop() }
        timeout = t
        main.postDelayed(t, args.timeoutMs ?: 60_000L)
    }

    private fun onTag(tag: Tag) {
        val dep = IsoDep.get(tag)
        if (dep == null) return // not ISO-DEP: keep waiting for the document
        try {
            dep.connect()
            dep.timeout = 5000
        } catch (e: Exception) {
            return
        }
        timeout?.let { main.removeCallbacks(it) }
        timeout = null
        isoDep = dep
        val id = UUID.randomUUID().toString()
        sessionId = id
        val out = JSObject()
        out.put("session", id)
        out.put("kind", "phone")
        waiting?.resolve(out)
        waiting = null
    }

    @Command
    fun transceive(invoke: Invoke) {
        val args = invoke.parseArgs(TransceiveArgs::class.java)
        val dep = isoDep
        if (dep == null || args.session != sessionId) { invoke.reject("No chip reading session is open."); return }
        val apdu = Base64.decode(args.apdu, Base64.NO_WRAP)
        io.execute {
            try {
                val r = dep.transceive(apdu)
                val out = JSObject()
                out.put("response", Base64.encodeToString(r, Base64.NO_WRAP))
                invoke.resolve(out)
            } catch (e: Exception) {
                invoke.reject("Lost contact with the chip. Hold the document still against the back of your phone and try again.")
            }
        }
    }

    @Command
    fun message(invoke: Invoke) {
        invoke.parseArgs(MessageArgs::class.java)
        invoke.resolve() // Android shows progress in the app itself
    }

    /** Stop waiting for a chip (the pending begin fails as cancelled) and close any session. */
    @Command
    fun cancel(invoke: Invoke) {
        waiting?.reject("Chip reading cancelled.")
        waiting = null
        stop()
        invoke.resolve()
    }

    @Command
    fun end(invoke: Invoke) {
        invoke.parseArgs(EndArgs::class.java)
        stop()
        invoke.resolve()
    }

    private fun stop() {
        timeout?.let { main.removeCallbacks(it) }
        timeout = null
        try { isoDep?.close() } catch (_: Exception) {}
        isoDep = null
        sessionId = null
        val a = adapter()
        main.post { try { a?.disableReaderMode(activity) } catch (_: Exception) {} }
    }
}
