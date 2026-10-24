// Android document camera (humid-docscan@2, Android 17+). CameraX: a PreviewView under the
// transparent web view, ImageAnalysis at about 720p for the guidance and the PDF417 reader,
// and a zero-shutter-lag ImageCapture from the same session (no teardown at the shutter).
//
//   focus      a real AF trigger (FocusMeteringAction) at the frame's centre, re-issued when it
//              auto-cancels so the region stays on the document; a tap does the same at the tap
//   AF state   CONTROL_AF_STATE and LENS_FOCUS_DISTANCE from the session's capture results:
//              "scanning" / "focused" / "failed", and the lens at its near limit (too close)
//   zoom       from LENS_INFO_MINIMUM_FOCUS_DISTANCE: z = 1.25 × MFD / d_fill(1×), at most 2.5
//   finding    Detect.kt (edges in the Y plane around the frame), then Guidance.kt (the shared rules)
//   PDF417     zxing-cpp on the Y plane, cropped to the frame, at most 4 times a second
//   still      ZSL where offered, kept in memory, cut out of the frame with Matrix.setPolyToPoly
//
// Nothing is written to disk or logged. A still lives in memory until `take` hands it over once.
// The preview is a TextureView (COMPATIBLE) inside the window, so FLAG_SECURE covers it.

package app.humid.docscan

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.Matrix
import android.graphics.Rect
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CaptureRequest
import android.hardware.camera2.CaptureResult
import android.hardware.camera2.TotalCaptureResult
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.view.HapticFeedbackConstants
import android.view.View
import android.view.ViewGroup
import android.webkit.WebView
import android.widget.FrameLayout
import androidx.annotation.OptIn
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.camera2.interop.Camera2CameraInfo
import androidx.camera.camera2.interop.Camera2Interop
import androidx.camera.camera2.interop.ExperimentalCamera2Interop
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalZeroShutterLag
import androidx.camera.core.FocusMeteringAction
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.AspectRatioStrategy
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Channel
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.json.JSONObject
import zxingcpp.BarcodeReader
import java.io.ByteArrayOutputStream
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.math.atan
import kotlin.math.max
import kotlin.math.min

@InvokeArg
class RectArg {
    var x: Double = 0.0
    var y: Double = 0.0
    var w: Double = 0.0
    var h: Double = 0.0
}

@InvokeArg
class SizeArg {
    var w: Double = 0.0
    var h: Double = 0.0
}

@InvokeArg
class ReadArg {
    var pdf417: Boolean = false
    var mrz: Boolean = false
    var require: Boolean = false
}

@InvokeArg
class OpenArgs {
    var shape: String = "id1"
    var read: ReadArg = ReadArg()
    var frame: RectArg = RectArg()
    var view: SizeArg = SizeArg()
    var auto: Boolean = true
    var haptics: Boolean = true
    lateinit var events: Channel
}

@InvokeArg
class FrameArgs {
    var frame: RectArg = RectArg()
    var view: SizeArg = SizeArg()
}

@InvokeArg
class PointArgs {
    var x: Double = 0.0
    var y: Double = 0.0
}

@InvokeArg
class TorchArgs {
    var on: Boolean = false
}

@InvokeArg
class TakeArgs {
    var id: String = ""
    var which: String = "doc"
}

private val RATIO = mapOf("id1" to 85.6 / 54.0, "td3" to 125.0 / 88.0, "page" to 1.35)
private val WIDTH_MM = mapOf("id1" to 85.6, "td3" to 125.0, "page" to 216.0)

/** A still in memory until `take` hands it over. */
private class Still(val id: String, var doc: Bitmap?, var full: Bitmap?)

@TauriPlugin(permissions = [Permission(strings = [Manifest.permission.CAMERA], alias = "camera")])
class HumidDocscanPlugin(private val activity: Activity) : Plugin(activity) {
    private val main = Handler(Looper.getMainLooper())
    private val work = Executors.newSingleThreadExecutor()
    private var web: WebView? = null
    private var preview: PreviewView? = null
    private var provider: ProcessCameraProvider? = null
    private var camera: Camera? = null
    private var imageCapture: ImageCapture? = null
    private var events: Channel? = null
    private var shape = "id1"
    private var reads = ReadArg()
    private var auto = true
    private var haptics = true
    private var frameCss = RectArg()
    private var viewCss = SizeArg()
    private var isOn = false
    private var paused = false
    private var busy = false
    private var pendingOpen: Invoke? = null

    // the camera's own state, from its capture results (any thread: read on the analysis thread)
    @Volatile private var afState: String? = null
    /** The preview's sensor → view transform, read on the main thread (it is @UiThread) for the analysis thread. */
    @Volatile private var sensorToView: Matrix? = null
    @Volatile private var viewWidth = 0
    private var lastViewRead = 0L
    @Volatile private var nearLimit = false
    private var minFocusDiopters = 0f
    private var focusCalibrated = false

    private val guidance = Guidance()
    private val detect = Detect()
    private var last: Look? = null
    private var lastSent = 0L
    private var lastBarcode = 0L
    private var lastAim = 0L
    private var codeRead = false
    private var alignedSince: Long? = null
    private var wasAligned = false
    private var still: Still? = null
    private val barcode by lazy {
        BarcodeReader(BarcodeReader.Options(formats = setOf(BarcodeReader.Format.PDF_417), tryHarder = true, tryRotate = true, textMode = BarcodeReader.TextMode.PLAIN, maxNumberOfSymbols = 1))
    }

    override fun load(webView: WebView) {
        super.load(webView)
        web = webView
    }

    /* ---------------- commands ---------------- */

    @Command
    fun probe(invoke: Invoke) {
        val pm = activity.packageManager
        val out = JSObject()
        val has = pm.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)
        out.put("available", has)
        out.put("lenses", JSArray().apply { put("wide") })
        out.put("macro", false)
        out.put("torch", pm.hasSystemFeature(PackageManager.FEATURE_CAMERA_FLASH))
        if (!has) out.put("reason", "This phone has no camera HumID can use.")
        invoke.resolve(out)
    }

    @Command
    fun open(invoke: Invoke) {
        val a = invoke.parseArgs(OpenArgs::class.java)
        if (a.shape !in listOf("id1", "td3", "page", "full")) { invoke.reject("invalid: shape"); return }
        shape = a.shape; reads = a.read; auto = a.auto; haptics = a.haptics; frameCss = a.frame; viewCss = a.view; events = a.events
        if (ContextCompat.checkSelfPermission(activity, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            pendingOpen = invoke
            requestPermissionForAlias("camera", invoke, "onCameraPermission")
            return
        }
        main.post { start(invoke) }
    }

    @PermissionCallback
    private fun onCameraPermission(invoke: Invoke) {
        pendingOpen = null
        if (ContextCompat.checkSelfPermission(activity, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            invoke.reject("denied: camera access is off for HumID")
            return
        }
        main.post { start(invoke) }
    }

    @Command
    fun frame(invoke: Invoke) {
        val a = invoke.parseArgs(FrameArgs::class.java)
        frameCss = a.frame; viewCss = a.view
        main.post { aimAtFrame() }
        invoke.resolve()
    }

    @Command
    fun focus(invoke: Invoke) {
        val a = invoke.parseArgs(PointArgs::class.java)
        main.post {
            val pv = preview; val cam = camera
            if (pv == null || cam == null) { invoke.reject("invalid: the camera isn't open."); return@post }
            val k = pv.width / max(1.0, viewCss.w)
            val (px, py) = Pair((a.x * k).toFloat(), (a.y * k).toFloat())
            val action = FocusMeteringAction.Builder(pv.meteringPointFactory.createPoint(px, py, 0.12f), FocusMeteringAction.FLAG_AF or FocusMeteringAction.FLAG_AE)
                .setAutoCancelDuration(2, TimeUnit.SECONDS).build()
            val f = cam.cameraControl.startFocusAndMetering(action)
            f.addListener({
                val ok = try { f.get().isFocusSuccessful } catch (_: Exception) { false }
                send(JSObject().apply { put("t", "focus"); put("x", a.x); put("y", a.y); put("af", if (ok) "focused" else "failed") })
                // back to the frame's centre once that has settled (plus the auto-cancel)
                main.postDelayed({ aimAtFrame() }, 2000)
            }, ContextCompat.getMainExecutor(activity))
            lastAim = System.currentTimeMillis() + 2500
            invoke.resolve()
        }
    }

    @Command
    fun torch(invoke: Invoke) {
        val a = invoke.parseArgs(TorchArgs::class.java)
        main.post {
            val cam = camera
            if (cam == null || !cam.cameraInfo.hasFlashUnit()) { invoke.reject("unavailable: no light"); return@post }
            cam.cameraControl.enableTorch(a.on)
            invoke.resolve(JSObject().apply { put("on", a.on) })
        }
    }

    @Command
    fun capture(invoke: Invoke) {
        main.post { shoot("shutter", invoke) }
    }

    @Command
    fun take(invoke: Invoke) {
        val a = invoke.parseArgs(TakeArgs::class.java)
        work.execute {
            val s = still
            if (s == null || s.id != a.id) { invoke.reject("invalid: that photo is gone"); return@execute }
            val bmp = if (a.which == "full") s.full.also { s.full = null } else s.doc.also { s.doc = null }
            if (s.doc == null && s.full == null) still = null
            if (bmp == null) { invoke.reject("invalid: that photo is gone"); return@execute }
            val buf = ByteArrayOutputStream()
            bmp.compress(Bitmap.CompressFormat.JPEG, 92, buf)
            bmp.recycle()
            invoke.resolve(JSObject().apply { put("data", Base64.encodeToString(buf.toByteArray(), Base64.NO_WRAP)) })
        }
    }

    @Command
    fun pause(invoke: Invoke) {
        main.post { paused = true; provider?.unbindAll(); camera = null; invoke.resolve() }
    }

    @Command
    fun resume(invoke: Invoke) {
        main.post {
            paused = false; busy = false
            guidance.reset(); last = null; codeRead = false; alignedSince = null; wasAligned = false
            still?.let { it.doc?.recycle(); it.full?.recycle() }; still = null
            if (isOn && camera == null) bind() // after a pause; otherwise the same session goes on
            invoke.resolve()
        }
    }

    @Command
    fun close(invoke: Invoke) {
        main.post { stop(); invoke.resolve() }
    }

    override fun onPause(activity: AppCompatActivity) {
        super.onPause(activity)
        if (isOn) { paused = true; main.post { provider?.unbindAll(); camera = null } }
    }

    /* ---------------- the camera ---------------- */

    private fun start(invoke: Invoke) {
        try {
            stop()
            val wv = web ?: throw IllegalStateException("no web view")
            val root = activity.findViewById<ViewGroup>(android.R.id.content)
            val pv = PreviewView(activity).apply {
                implementationMode = PreviewView.ImplementationMode.COMPATIBLE // a TextureView: FLAG_SECURE covers it
                scaleType = PreviewView.ScaleType.FILL_CENTER
                layoutParams = FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            }
            // under the web view: the web view's parent holds both, the preview first
            val parent = (wv.parent as? ViewGroup) ?: root
            parent.addView(pv, 0)
            wv.setBackgroundColor(Color.TRANSPARENT)
            preview = pv
            isOn = true; paused = false; busy = false
            val f = ProcessCameraProvider.getInstance(activity)
            f.addListener({
                try {
                    provider = f.get()
                    bind()
                    invoke.resolve(JSObject().apply { put("session", UUID.randomUUID().toString()) })
                } catch (e: Exception) {
                    stop()
                    invoke.reject("failed: ${e.message ?: "the camera couldn't start"}")
                }
            }, ContextCompat.getMainExecutor(activity))
        } catch (e: Exception) {
            stop()
            invoke.reject("failed: ${e.message ?: "the camera couldn't start"}")
        }
    }

    @OptIn(ExperimentalCamera2Interop::class, ExperimentalZeroShutterLag::class)
    private fun bind() {
        val prov = provider ?: return
        val pv = preview ?: return
        val owner = activity as? LifecycleOwner ?: throw IllegalStateException("not a lifecycle owner")
        prov.unbindAll()
        val sel = CameraSelector.DEFAULT_BACK_CAMERA
        val info = prov.getCameraInfo(sel)
        val c2 = Camera2CameraInfo.from(info)
        minFocusDiopters = c2.getCameraCharacteristic(CameraCharacteristics.LENS_INFO_MINIMUM_FOCUS_DISTANCE) ?: 0f
        focusCalibrated = (c2.getCameraCharacteristic(CameraCharacteristics.LENS_INFO_FOCUS_DISTANCE_CALIBRATION)
            ?: CameraCharacteristics.LENS_INFO_FOCUS_DISTANCE_CALIBRATION_UNCALIBRATED) != CameraCharacteristics.LENS_INFO_FOCUS_DISTANCE_CALIBRATION_UNCALIBRATED

        // 4:3 like the still, so the preview and the photo see the same field (the frame maps straight across)
        val previewBuilder = Preview.Builder().setResolutionSelector(ResolutionSelector.Builder()
            .setAspectRatioStrategy(AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY).build())
        // the camera's own AF state and lens position, every frame
        Camera2Interop.Extender(previewBuilder).setSessionCaptureCallback(object : CameraCaptureSession.CaptureCallback() {
            override fun onCaptureCompleted(session: CameraCaptureSession, request: CaptureRequest, result: TotalCaptureResult) {
                afState = when (result.get(CaptureResult.CONTROL_AF_STATE)) {
                    CaptureResult.CONTROL_AF_STATE_PASSIVE_SCAN, CaptureResult.CONTROL_AF_STATE_ACTIVE_SCAN -> "scanning"
                    CaptureResult.CONTROL_AF_STATE_PASSIVE_FOCUSED, CaptureResult.CONTROL_AF_STATE_FOCUSED_LOCKED -> "focused"
                    CaptureResult.CONTROL_AF_STATE_PASSIVE_UNFOCUSED, CaptureResult.CONTROL_AF_STATE_NOT_FOCUSED_LOCKED -> "failed"
                    else -> null
                }
                val d = result.get(CaptureResult.LENS_FOCUS_DISTANCE) ?: 0f
                nearLimit = minFocusDiopters > 0f && d >= minFocusDiopters * 0.95f
            }
        })
        val prev = previewBuilder.build().also { it.setSurfaceProvider(pv.surfaceProvider) }

        val analysis = ImageAnalysis.Builder()
            .setResolutionSelector(ResolutionSelector.Builder()
                .setAspectRatioStrategy(AspectRatioStrategy.RATIO_16_9_FALLBACK_AUTO_STRATEGY)
                .setResolutionStrategy(ResolutionStrategy(android.util.Size(1280, 720), ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER))
                .build())
            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
            .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)
            .build()
        analysis.setAnalyzer(work) { img -> img.use { analyse(it) } }

        val zsl = info.isZslSupported
        val cap = ImageCapture.Builder()
            .setCaptureMode(if (zsl) ImageCapture.CAPTURE_MODE_ZERO_SHUTTER_LAG else ImageCapture.CAPTURE_MODE_MAXIMIZE_QUALITY)
            .setResolutionSelector(ResolutionSelector.Builder()
                .setAspectRatioStrategy(AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY)
                .setResolutionStrategy(ResolutionStrategy(android.util.Size(4000, 3000), ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER))
                .build())
            .setJpegQuality(92)
            .build()
        imageCapture = cap
        pv.display?.let { prev.setTargetRotation(it.rotation) }
        val cam = prov.bindToLifecycle(owner, sel, prev, analysis, cap)
        camera = cam
        val z = zoom(info)
        if (z > 1.0) cam.cameraControl.setZoomRatio(z.toFloat())
        pv.post { aimAtFrame(); readView() }
        send(JSObject().apply {
            put("t", "ready"); put("lens", "wide"); put("zoom", z); put("torch", info.hasFlashUnit())
            if (minFocusDiopters > 0f && focusCalibrated) put("minFocusMm", 1000.0 / minFocusDiopters)
        })
    }

    /**
     * z = clamp(1.25 × MFD / d_fill(1×), 1, min(2.5, max zoom)): the document fills the frame from beyond the
     * lens's minimum focus distance. Only from a calibrated MFD; otherwise 1 (the near-limit check still works).
     */
    @OptIn(ExperimentalCamera2Interop::class)
    private fun zoom(info: androidx.camera.core.CameraInfo): Double {
        if (shape == "full" || shape == "page" || !focusCalibrated || minFocusDiopters <= 0f) return 1.0
        val c2 = Camera2CameraInfo.from(info)
        val sensor = c2.getCameraCharacteristic(CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE) ?: return 1.0
        val focal = c2.getCameraCharacteristic(CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS)?.firstOrNull() ?: return 1.0
        val pv = preview ?: return 1.0
        // the preview fills the view (FILL_CENTER); in portrait the sensor's short side runs across
        val shortSide = min(sensor.width, sensor.height).toDouble()
        val longSide = max(sensor.width, sensor.height).toDouble()
        val viewAspect = pv.width.toDouble() / max(1, pv.height)
        val across = if (viewAspect * longSide < shortSide) viewAspect * longSide else shortSide // the visible sensor width
        val fov = 2 * atan(across / 2 / focal)
        val frac = frameCss.w / max(1.0, viewCss.w)
        val dFill = (WIDTH_MM[shape] ?: 85.6) / 2 / (kotlin.math.tan(fov / 2) * frac)
        val mfd = 1000.0 / minFocusDiopters
        val maxZ = camera?.cameraInfo?.zoomState?.value?.maxZoomRatio?.toDouble() ?: 2.5
        return (1.25 * mfd / dFill).coerceIn(1.0, min(2.5, maxZ))
    }

    /** A real AF and AE trigger at the frame's centre, auto-cancelled after 4 s (then CameraX goes back to continuous). */
    private fun aimAtFrame() {
        val pv = preview ?: return
        val cam = camera ?: return
        if (pv.width == 0) return
        val k = pv.width / max(1.0, viewCss.w)
        val cx = ((frameCss.x + frameCss.w / 2) * k).toFloat()
        val cy = ((frameCss.y + frameCss.h / 2) * k).toFloat()
        val action = FocusMeteringAction.Builder(pv.meteringPointFactory.createPoint(cx, cy, 0.15f), FocusMeteringAction.FLAG_AF or FocusMeteringAction.FLAG_AE)
            .setAutoCancelDuration(4, TimeUnit.SECONDS).build()
        cam.cameraControl.startFocusAndMetering(action)
        lastAim = System.currentTimeMillis()
    }

    /* ---------------- each frame ---------------- */

    /** Read the preview's transform on the main thread (layout, rotation and zoom change it). */
    private fun readView() {
        val pv = preview ?: return
        sensorToView = pv.sensorToViewTransform
        viewWidth = pv.width
    }

    /** The analysis picture's pixels → CSS pixels of the web view, through the preview's own transform. */
    private fun toCss(img: ImageProxy): Matrix? {
        val now = System.currentTimeMillis()
        if (now - lastViewRead > 500) { lastViewRead = now; main.post { readView() } }
        val s2v = sensorToView ?: return null
        val sensorToBuffer = img.imageInfo.sensorToBufferTransformMatrix
        val bufferToSensor = Matrix().also { if (!sensorToBuffer.invert(it)) return null }
        val m = Matrix(bufferToSensor)
        m.postConcat(s2v)
        val k = (viewCss.w / max(1, viewWidth)).toFloat()
        m.postScale(k, k)
        return m
    }

    private fun analyse(img: ImageProxy) {
        if (!isOn || paused || busy) return
        val now = System.currentTimeMillis()
        val css = toCss(img) ?: return
        val toBuf = Matrix().also { if (!css.invert(it)) return }
        // the frame (or the whole view, for a Photo) in the analysis buffer's pixels
        val fr = if (shape == "full") floatArrayOf(0f, 0f, viewCss.w.toFloat(), viewCss.h.toFloat())
                 else floatArrayOf(frameCss.x.toFloat(), frameCss.y.toFloat(), (frameCss.x + frameCss.w).toFloat(), (frameCss.y + frameCss.h).toFloat())
        toBuf.mapPoints(fr)
        val bx = min(fr[0], fr[2]); val by = min(fr[1], fr[3]); val bw = kotlin.math.abs(fr[2] - fr[0]); val bh = kotlin.math.abs(fr[3] - fr[1])
        val y = img.planes[0]
        val found = detect.find(y.buffer, y.rowStride, img.width, img.height, Box(bx.toDouble(), by.toDouble(), bw.toDouble(), bh.toDouble()), shape)
        var quadCss: List<DoubleArray>? = null
        var fit: String? = null
        if (found != null) {
            val pts = FloatArray(8) { i -> found.quad[i / 2][i % 2].toFloat() }
            css.mapPoints(pts)
            // the buffer is the sensor's way round: start the corners at the screen's top left (the order stays clockwise)
            val q = (0 until 4).map { doubleArrayOf(pts[it * 2].toDouble(), pts[it * 2 + 1].toDouble()) }
            val first = q.indices.minByOrNull { q[it][0] + q[it][1] } ?: 0
            quadCss = (0 until 4).map { q[(first + it) % 4] }
            fit = if (shape == "full") (if (found.area < 0.12) "far" else null)
                  else fitOf(quadCss, Box(frameCss.x, frameCss.y, frameCss.w, frameCss.h), if (shape == "page") null else RATIO[shape])
        }
        // the barcode, read in the pipeline while a card is in the frame (at most 4 a second)
        if (reads.pdf417 && !codeRead && found != null && now - lastBarcode >= 250) {
            lastBarcode = now
            try {
                img.setCropRect(Rect(bx.toInt().coerceAtLeast(0), by.toInt().coerceAtLeast(0), (bx + bw).toInt().coerceAtMost(img.width), (by + bh).toInt().coerceAtMost(img.height)))
                val text = barcode.read(img).firstOrNull { it.text != null }?.text
                if (text != null && text.length in 20..4000) {
                    codeRead = true
                    send(JSObject().apply { put("t", "code"); put("kind", "pdf417"); put("state", "read"); put("text", text) })
                }
            } catch (_: Exception) { /* a bad frame: keep looking */ }
        }
        val aligned = found != null && fit == null
        if (aligned) { if (alignedSince == null) alignedSince = now } else alignedSince = null
        // a side with a barcode waits for it (2.5 s at most once lined up); the MRZ is read from the still (audit: no live MRZ on Android)
        val wait = reads.require && reads.pdf417 && !codeRead && (alignedSince?.let { now - it < Rules.CODE_WAIT_MS } ?: true)
        val m = Measure(found = found != null, quad = quadCss, fit = fit, light = found?.light ?: (if (detect.dark) "dark" else "ok"),
            focus = afState, near = nearLimit, sharp = found?.sharp, steady = found?.steady, wait = wait)
        val look = guidance.feed(m, now)
        if (look.aligned && !wasAligned) haptic(HapticFeedbackConstants.GESTURE_THRESHOLD_ACTIVATE)
        wasAligned = look.aligned
        // keep the AF region on the document: CameraX goes back to continuous AF when the action auto-cancels
        if (aligned && now - lastAim > 4200) main.post { aimAtFrame() }
        if ((changed(last, look) && now - lastSent >= 100) || look.fire) {
            last = look; lastSent = now
            send(lookJson(look))
        }
        if (look.fire && auto) main.post { shoot("auto", null) }
    }

    private fun lookJson(l: Look) = JSObject().apply {
        put("t", "look"); put("state", l.state); put("key", l.key ?: JSONObject.NULL); put("aligned", l.aligned)
        put("quad", l.quad?.let { q -> JSArray().apply { q.forEach { p -> put(JSArray().apply { put(p[0]); put(p[1]) }) } } } ?: JSONObject.NULL)
        put("focus", l.focus ?: JSONObject.NULL); put("steady", l.steady); put("light", l.light); put("progress", l.progress); put("lens", "wide")
    }

    /* ---------------- the still ---------------- */

    /** Take the photo from the running session; if the camera isn't in focus, focus first (500 ms at most). */
    private fun shoot(how: String, invoke: Invoke?) {
        val cap = imageCapture
        if (cap == null || busy || !isOn) { invoke?.reject("invalid: the camera isn't ready"); return }
        busy = true
        val go = {
            cap.takePicture(work, object : ImageCapture.OnImageCapturedCallback() {
                override fun onCaptureSuccess(image: ImageProxy) {
                    try {
                        val s = cut(image)
                        still?.let { it.doc?.recycle(); it.full?.recycle() }
                        still = s
                        val freeze = s.doc?.let { b ->
                            val k = 720.0 / max(b.width, b.height)
                            val small = Bitmap.createScaledBitmap(b, max(1, (b.width * k).toInt()), max(1, (b.height * k).toInt()), true)
                            val buf = ByteArrayOutputStream(); small.compress(Bitmap.CompressFormat.JPEG, 72, buf); small.recycle()
                            Base64.encodeToString(buf.toByteArray(), Base64.NO_WRAP)
                        }
                        haptic(HapticFeedbackConstants.CONFIRM)
                        invoke?.resolve(JSObject().apply { put("id", s.id); put("width", s.doc?.width ?: 0); put("height", s.doc?.height ?: 0) })
                        send(JSObject().apply {
                            put("t", "captured"); put("id", s.id); put("how", how); put("width", s.doc?.width ?: 0); put("height", s.doc?.height ?: 0)
                            put("cut", lastQuadFound); put("freeze", freeze ?: JSONObject.NULL); put("codes", JSObject()); put("af", afState ?: "focused"); put("lens", "wide")
                        })
                    } catch (e: Exception) {
                        busy = false
                        invoke?.reject("failed: ${e.message}")
                        send(JSObject().apply { put("t", "error"); put("code", "failed"); put("message", "Couldn't take the photo. Try again."); put("soft", true) })
                    } finally { image.close() }
                }
                override fun onError(e: ImageCaptureException) {
                    busy = false
                    haptic(HapticFeedbackConstants.REJECT)
                    invoke?.reject("failed: ${e.message}")
                    send(JSObject().apply { put("t", "error"); put("code", "failed"); put("message", "Couldn't take the photo. Try again."); put("soft", true) })
                }
            })
        }
        if (afState == "focused" || camera == null) go()
        else {
            val pv = preview; val cam = camera!!
            val k = (pv?.width ?: 1) / max(1.0, viewCss.w)
            val action = FocusMeteringAction.Builder(pv!!.meteringPointFactory.createPoint(((frameCss.x + frameCss.w / 2) * k).toFloat(), ((frameCss.y + frameCss.h / 2) * k).toFloat(), 0.15f), FocusMeteringAction.FLAG_AF)
                .setAutoCancelDuration(2, TimeUnit.SECONDS).build()
            val f = cam.cameraControl.startFocusAndMetering(action)
            var done = false
            val once = { if (!done) { done = true; go() } }
            f.addListener({ once() }, ContextCompat.getMainExecutor(activity))
            main.postDelayed({ once() }, 500)
        }
    }

    private var lastQuadFound = false

    /** The still, upright, and the document cut out of it (the quad found again in the still, or the frame). */
    private fun cut(image: ImageProxy): Still {
        val raw = image.toBitmap()
        val rot = image.imageInfo.rotationDegrees
        val full = if (rot != 0) Bitmap.createBitmap(raw, 0, 0, raw.width, raw.height, Matrix().apply { postRotate(rot.toFloat()) }, true).also { raw.recycle() } else raw
        val id = UUID.randomUUID().toString().replace("-", "").take(24)
        if (shape == "full") { lastQuadFound = false; return Still(id, full, null) }
        // where the frame is in the still: the still and the preview share the view port (same session)
        val sx = full.width / max(1.0, viewCss.w); val sy = full.height / max(1.0, viewCss.h)
        val s = max(sx, sy) // FILL_CENTER: the view is the still's centre crop
        val ox = (full.width - viewCss.w * s) / 2; val oy = (full.height - viewCss.h * s) / 2
        val frame = Box(ox + frameCss.x * s, oy + frameCss.y * s, frameCss.w * s, frameCss.h * s)
        val grey = Detect.grey(full, 640)
        val k = grey.w / full.width.toDouble()
        val q = detect.findIn(grey, Box(frame.x * k, frame.y * k, frame.w * k, frame.h * k), shape)
        lastQuadFound = q != null
        val quad = q?.quad?.map { doubleArrayOf(it[0] / k, it[1] / k) }
            ?: listOf(doubleArrayOf(frame.x, frame.y), doubleArrayOf(frame.x + frame.w, frame.y), doubleArrayOf(frame.x + frame.w, frame.y + frame.h), doubleArrayOf(frame.x, frame.y + frame.h))
        val outW = when (shape) { "td3" -> 2000; "page" -> 1925; else -> 1600 }
        val ratio = RATIO[shape] ?: 1.585
        val outH = if (shape == "page") (outW * ratio).toInt() else (outW / ratio).toInt()
        val doc = Bitmap.createBitmap(outW, outH, Bitmap.Config.ARGB_8888)
        val m = Matrix()
        val src = floatArrayOf(quad[0][0].toFloat(), quad[0][1].toFloat(), quad[1][0].toFloat(), quad[1][1].toFloat(), quad[2][0].toFloat(), quad[2][1].toFloat(), quad[3][0].toFloat(), quad[3][1].toFloat())
        val dst = floatArrayOf(0f, 0f, outW.toFloat(), 0f, outW.toFloat(), outH.toFloat(), 0f, outH.toFloat())
        m.setPolyToPoly(src, 0, dst, 0, 4)
        android.graphics.Canvas(doc).drawBitmap(full, m, android.graphics.Paint(android.graphics.Paint.FILTER_BITMAP_FLAG))
        val keepFull = if (shape == "page") full else { full.recycle(); null }
        return Still(id, doc, keepFull)
    }

    /* ---------------- plumbing ---------------- */

    private fun send(o: JSObject) {
        try { events?.send(o) } catch (_: Exception) { /* the screen is gone */ }
    }

    private fun haptic(kind: Int) {
        if (!haptics) return
        main.post { web?.performHapticFeedback(kind) }
    }

    private fun stop() {
        isOn = false; paused = false; busy = false
        provider?.unbindAll()
        camera = null; imageCapture = null
        preview?.let { (it.parent as? ViewGroup)?.removeView(it) }
        preview = null
        web?.setBackgroundColor(Color.BLACK)
        guidance.reset(); last = null; codeRead = false; alignedSince = null; wasAligned = false
        still?.let { it.doc?.recycle(); it.full?.recycle() }; still = null
    }

    override fun onDestroy(activity: AppCompatActivity) {
        super.onDestroy(activity)
        main.post { stop() }
    }
}
