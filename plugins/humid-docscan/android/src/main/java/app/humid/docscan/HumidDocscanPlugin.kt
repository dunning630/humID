// Android document capture (humid-docscan@1). Opens the phone's own document scanner
// (ML Kit, delivered by Google Play services) for one page, in "base" mode: it finds
// the edges, captures when steady and flattens the page, and the person can only crop
// or turn it (no filters, no ML clean-up that could change what a document says). The
// page comes back as JPEG bytes and the scanner's copy is deleted at once. The scanning
// runs on the phone; the picture never leaves it. Reading and sealing stay in the JS.

package app.humid.docscan

import android.app.Activity
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.util.Base64
import android.webkit.WebView
import androidx.activity.result.ActivityResult
import androidx.activity.result.IntentSenderRequest
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import com.google.mlkit.vision.documentscanner.GmsDocumentScannerOptions
import com.google.mlkit.vision.documentscanner.GmsDocumentScanning
import com.google.mlkit.vision.documentscanner.GmsDocumentScanningResult
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.Executors

@InvokeArg
class ScanArgs {
    var maxSide: Int? = null
}

@TauriPlugin
class HumidDocscanPlugin(private val activity: Activity) : Plugin(activity) {
    private val io = Executors.newSingleThreadExecutor()
    private var maxSide = 3200
    private val prefs by lazy { activity.getSharedPreferences("humid-docscan", Activity.MODE_PRIVATE) }

    /** At start-up, and before each scan: remove any page a scan left behind (HumID stopped before it could delete it). */
    override fun load(webView: WebView) {
        super.load(webView)
        io.execute { sweep() }
    }

    /**
     * The scanner writes its page into this app's own storage. Pages are deleted once read;
     * one can only be left if HumID was stopped in between. Clears the folder the last page
     * came from, and any scanner folder in the app's cache (by its name).
     */
    private fun sweep() {
        try {
            prefs.getString("dir", null)?.let { File(it).listFiles()?.forEach { f -> if (f.isFile) f.delete() } }
            val named = Regex("(?i)mlkit|docscan|document_?scan")
            fun walk(dir: File?, depth: Int) {
                if (dir == null || depth > 3) return
                dir.listFiles()?.forEach { f ->
                    if (f.isDirectory) {
                        if (named.containsMatchIn(f.name)) f.walkBottomUp().forEach { x -> if (x.isFile) x.delete() }
                        else walk(f, depth + 1)
                    }
                }
            }
            walk(activity.cacheDir, 0) // the scanner's working copies live in the cache; nothing else of HumID's is named like it
        } catch (_: Exception) { /* best effort: nothing else depends on it */ }
    }

    @Command
    fun probe(invoke: Invoke) {
        // The real check is opening the scanner: Play services, its scanner module and
        // enough memory are only known then, and a failure there says "unavailable".
        val out = JSObject()
        out.put("available", true)
        invoke.resolve(out)
    }

    @Command
    fun scan(invoke: Invoke) {
        val args = invoke.parseArgs(ScanArgs::class.java)
        maxSide = (args.maxSide ?: 3200).coerceIn(800, 6000)
        io.execute { sweep() }
        val options = GmsDocumentScannerOptions.Builder()
            .setScannerMode(GmsDocumentScannerOptions.SCANNER_MODE_BASE)
            .setGalleryImportAllowed(false)
            .setPageLimit(1)
            .setResultFormats(GmsDocumentScannerOptions.RESULT_FORMAT_JPEG)
            .build()
        try {
            GmsDocumentScanning.getClient(options).getStartScanIntent(activity)
                .addOnSuccessListener { sender ->
                    try {
                        startIntentSenderForResult(invoke, IntentSenderRequest.Builder(sender).build(), "onScanned")
                    } catch (e: Exception) {
                        invoke.reject("unavailable: ${e.message ?: "the scanner couldn't open"}")
                    }
                }
                .addOnFailureListener { e -> invoke.reject("unavailable: ${e.message ?: "the scanner couldn't start"}") }
        } catch (e: Exception) {
            invoke.reject("unavailable: ${e.message ?: "no document scanner on this phone"}")
        }
    }

    @ActivityCallback
    private fun onScanned(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode != Activity.RESULT_OK) { invoke.reject("cancelled"); return }
        val scanned = GmsDocumentScanningResult.fromActivityResultIntent(result.data)
        val uri = scanned?.pages?.firstOrNull()?.imageUri
        if (uri == null) { invoke.reject("cancelled"); return }
        if (uri.scheme == "file") uri.path?.let { File(it).parent }?.let { prefs.edit().putString("dir", it).apply() }
        io.execute {
            try {
                val out = page(uri)
                invoke.resolve(out)
            } catch (e: Exception) {
                invoke.reject("The scanned page couldn't be read: ${e.message ?: "unknown error"}")
            } finally {
                forget(uri)
            }
        }
    }

    /** The page as a JPEG no longer than maxSide on its long side: the scanner's own bytes when they fit. */
    private fun page(uri: Uri): JSObject {
        val bytes = activity.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IllegalStateException("no data")
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        var w = bounds.outWidth
        var h = bounds.outHeight
        if (w <= 0 || h <= 0) throw IllegalStateException("not a picture")
        val jpeg: ByteArray
        if (maxOf(w, h) <= maxSide) {
            jpeg = bytes
        } else {
            var sample = 1
            while (maxOf(w, h) / (sample * 2) >= maxSide) sample *= 2
            val decoded = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sample })
                ?: throw IllegalStateException("not a picture")
            val k = maxSide.toDouble() / maxOf(decoded.width, decoded.height)
            val scaled = if (k < 1.0) Bitmap.createScaledBitmap(decoded, (decoded.width * k).toInt().coerceAtLeast(1), (decoded.height * k).toInt().coerceAtLeast(1), true) else decoded
            val buf = ByteArrayOutputStream()
            scaled.compress(Bitmap.CompressFormat.JPEG, 92, buf)
            w = scaled.width
            h = scaled.height
            if (scaled !== decoded) scaled.recycle()
            decoded.recycle()
            jpeg = buf.toByteArray()
        }
        val out = JSObject()
        out.put("data", Base64.encodeToString(jpeg, Base64.NO_WRAP))
        out.put("mime", "image/jpeg")
        out.put("width", w)
        out.put("height", h)
        return out
    }

    /** The scanner leaves its page in this app's storage: delete it once read. */
    private fun forget(uri: Uri) {
        try {
            if (uri.scheme == "file") uri.path?.let { File(it).delete() }
            else activity.contentResolver.delete(uri, null, null)
        } catch (_: Exception) { /* not ours to delete, or already gone */ }
    }
}
