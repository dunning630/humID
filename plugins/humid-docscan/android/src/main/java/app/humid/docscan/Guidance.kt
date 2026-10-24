// The document camera's guidance: a line-by-line port of apps/mobile/src/core/lookstate.js
// (the one set of rules every HumID camera follows). Plain Kotlin, no Android, so it is unit
// tested on the JVM against the same golden vectors (tests/fixtures/guidance.json).
//
// Feed it one frame's measurements; it says what the camera screen should show, and when to
// take the photo. A problem is said once it has lasted; "focusing" only while the camera's
// own autofocus has been moving for FOCUSING_MS; the frame never changes size.

package app.humid.docscan

import kotlin.math.abs
import kotlin.math.atan2
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min

object Rules {
    val SAY_MS = mapOf("dark" to 600L, "glare" to 500L, "hold" to 450L, "tooclose" to 0L, "showback" to 1200L, "showfront" to 1200L, "showpage" to 1500L)
    const val SAY_DEFAULT = 350L
    const val SWITCH_MS = 550L
    const val FOCUSING_MS = 250L
    const val TOO_CLOSE_MS = 600L
    const val HOLD_MS = 300L
    const val GRACE_MS = 300L
    const val CODE_WAIT_MS = 2500L

    // geometry, as shares of the frame
    const val SMALL = 0.78
    const val SNUG = 0.88
    const val BIG = 1.06
    const val SHIFT = 0.045
    const val TILT_DEG = 6.0
    const val FLAT = 0.1
    const val RATIO = 0.14

    fun sayAfter(key: String): Long = SAY_MS[key] ?: SAY_DEFAULT
}

/** A rectangle (the frame), in the same units as the quad. */
data class Box(val x: Double, val y: Double, val w: Double, val h: Double)

/** One frame's measurements (lookstate.js feed's `m`). */
data class Measure(
    val found: Boolean,
    val quad: List<DoubleArray>? = null,
    val fit: String? = null,
    val light: String = "ok",
    /** "scanning" | "focused" | "failed" | null */
    val focus: String? = null,
    val near: Boolean = false,
    val sharp: Boolean? = null,
    val steady: Boolean? = null,
    val wrong: String? = null,
    val wait: Boolean = false,
)

/** One look (lookstate.js feed's result). */
data class Look(
    val state: String,
    val key: String?,
    val aligned: Boolean,
    val quad: List<DoubleArray>?,
    val focus: String?,
    val steady: Boolean,
    val light: String,
    val progress: Double,
    val fire: Boolean,
)

/** How a found document sits in the frame: a guide key, or null when it is lined up. quad: tl, tr, br, bl. */
fun fitOf(quad: List<DoubleArray>, frame: Box, ratio: Double?): String? {
    fun d(a: DoubleArray, b: DoubleArray) = hypot(a[0] - b[0], a[1] - b[1])
    val (tl, tr, br, bl) = quad
    val top = d(tl, tr); val bottom = d(bl, br); val left = d(tl, bl); val right = d(tr, br)
    val across = (top + bottom) / 2; val down = (left + right) / 2
    if (!(across > 0 && down > 0)) return "shape"
    if (ratio != null && abs(across / down / ratio - 1) > Rules.RATIO) return "shape"
    val scale = max(across / frame.w, down / frame.h)
    if (scale < Rules.SMALL) return "closer"
    if (scale < Rules.SNUG) return "fill"
    if (scale > Rules.BIG) return "back"
    val cx = (tl[0] + tr[0] + br[0] + bl[0]) / 4; val cy = (tl[1] + tr[1] + br[1] + bl[1]) / 4
    if (abs(cx - (frame.x + frame.w / 2)) / frame.w > Rules.SHIFT || abs(cy - (frame.y + frame.h / 2)) / frame.h > Rules.SHIFT) return "shift"
    val deg = (atan2(tr[1] - tl[1], tr[0] - tl[0]) + atan2(br[1] - bl[1], br[0] - bl[0])) / 2 * 180 / Math.PI
    if (abs(deg) > Rules.TILT_DEG) return "tilt"
    if (abs(top - bottom) / across > Rules.FLAT || abs(left - right) / down > Rules.FLAT) return "flat"
    return null
}

class Guidance {
    private var shown: String? = null
    private var candKey: String? = null
    private var candSince = 0L
    private var scanSince: Long? = null
    private var closeSince: Long? = null
    private var holdSince: Long? = null
    private var lastGood: Long? = null
    private var fired = false

    fun feed(m: Measure, now: Long): Look {
        val found = m.found
        val light = m.light
        val focus = m.focus
        var state: String
        var raw: String? = null
        var aligned = false
        var close = false
        if (light == "dark") { state = if (found) "aligning" else "searching"; raw = "dark" }
        else if (!found) state = "searching"
        else if (m.fit != null) { state = "aligning"; raw = m.fit }
        else if (m.wrong != null) { state = "aligning"; raw = m.wrong }
        else {
            aligned = true
            state = "sharp"
            if (focus == "scanning") {
                val since = scanSince ?: now.also { scanSince = it }
                if (now - since >= Rules.FOCUSING_MS) state = "focusing"
            } else scanSince = null
            close = m.near || focus == "failed"
            if (close) { if (closeSince == null) closeSince = now } else closeSince = null
            val cs = closeSince
            if (cs != null && now - cs >= Rules.TOO_CLOSE_MS) raw = "tooclose"
            else if (light == "glare" || light == "bright") raw = light
            else if (m.steady == false || m.sharp == false) raw = if (state == "focusing") null else "hold"
        }
        if (!aligned) { scanSince = null; closeSince = null }
        val good = aligned && raw == null && !close && !m.wait && focus != "scanning"
        if (good) { if (holdSince == null) holdSince = now; lastGood = now }
        else if (!found || (holdSince != null && now - (lastGood ?: now) > Rules.GRACE_MS)) holdSince = null
        val hs = holdSince
        var progress = if (hs != null && good) min(1.0, (now - hs).toDouble() / Rules.HOLD_MS) else 0.0
        var fire = false
        if (good && hs != null && now - hs >= Rules.HOLD_MS && !fired) { fired = true; fire = true; state = "ready"; progress = 1.0 }
        else if (fired && aligned) { state = "ready"; progress = 1.0 }
        if (raw == null) { shown = null; candKey = null }
        else if (raw == shown) candKey = null
        else {
            if (candKey != raw) { candKey = raw; candSince = now }
            val wait = if (shown != null) max(Rules.SWITCH_MS, Rules.sayAfter(raw)) else Rules.sayAfter(raw)
            if (now - candSince >= wait) { shown = raw; candKey = null }
        }
        return Look(state, shown, aligned, if (found) m.quad else null, focus, m.steady != false, light, progress, fire)
    }

    fun reset() { shown = null; candKey = null; scanSince = null; closeSince = null; holdSince = null; lastGood = null; fired = false }
}

/** Is `b` worth sending after `a`? (lookstate.js changed) */
fun changed(a: Look?, b: Look): Boolean {
    if (a == null) return true
    if (a.state != b.state || a.key != b.key || a.focus != b.focus || a.light != b.light || a.steady != b.steady || a.aligned != b.aligned) return true
    if (Math.round(a.progress * 10) != Math.round(b.progress * 10)) return true
    val aq = a.quad; val bq = b.quad
    if ((aq == null) != (bq == null)) return true
    if (aq == null || bq == null) return false
    val size = hypot(bq[0][0] - bq[2][0], bq[0][1] - bq[2][1]).takeIf { it > 0 } ?: 1.0
    return bq.indices.any { i -> hypot(bq[i][0] - aq[i][0], bq[i][1] - aq[i][1]) > size * 0.01 }
}
