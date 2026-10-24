// One look at an analysis frame (Android): the document's corners in the Y plane around the
// frame (DocFind.kt), the light inside them, whether they hold still, and whether the picture
// is blurred by motion (a Laplacian measure against this card's own recent best; it never
// says "focusing": that comes only from the camera's AF state).
//
// Works on the Y plane in place (no copy of the frame, no RGB): the part round the frame is
// sampled straight into a 256 px grey picture.

package app.humid.docscan

import android.graphics.Bitmap
import java.nio.ByteBuffer
import kotlin.math.abs
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min

class Seen(val quad: List<DoubleArray>, val area: Double, val light: String, val steady: Boolean, val sharp: Boolean?)

class Detect {
    private val history = ArrayDeque<Pair<Long, List<DoubleArray>>>()
    private val sharpness = ArrayDeque<Double>()
    /** The last frame with no document in it was dark all over. */
    var dark = false
        private set

    /**
     * The document in the frame `box` (buffer pixels) and 30% round it, or the whole buffer for a Photo.
     * Returns its corners in buffer pixels, or null.
     */
    fun find(y: ByteBuffer, stride: Int, w: Int, h: Int, box: Box, shape: String): Seen? {
        val full = shape == "full"
        val x0 = if (full) 0.0 else max(0.0, box.x - box.w * 0.3)
        val y0 = if (full) 0.0 else max(0.0, box.y - box.h * 0.3)
        val x1 = if (full) w.toDouble() else min(w.toDouble(), box.x + box.w * 1.3)
        val y1 = if (full) h.toDouble() else min(h.toDouble(), box.y + box.h * 1.3)
        val aw = x1 - x0; val ah = y1 - y0
        if (aw < 32 || ah < 32) return null
        val k = 256.0 / max(aw, ah)
        val gw = max(32, (aw * k).toInt()); val gh = max(32, (ah * k).toInt())
        val g = IntArray(gw * gh)
        // a 2×2 average per sample: cheap, and enough against the sensor's grain
        for (yy in 0 until gh) {
            val sy = min(h - 2, (y0 + yy / k).toInt())
            for (xx in 0 until gw) {
                val sx = min(w - 2, (x0 + xx / k).toInt())
                val o = sy * stride + sx
                g[yy * gw + xx] = ((y.get(o).toInt() and 0xff) + (y.get(o + 1).toInt() and 0xff) + (y.get(o + stride).toInt() and 0xff) + (y.get(o + stride + 1).toInt() and 0xff)) / 4
            }
        }
        val im = Grey(gw, gh, g)
        val ratio = when (shape) { "id1" -> 1.586; "td3" -> 1.42; else -> null }
        val f = DocFind.find(im, if (full) 0.03 else 0.1, ratio)
        if (f == null) { history.clear(); sharpness.clear(); dark = darkAll(im); return null }
        dark = false
        val quad = f.quad.map { doubleArrayOf(x0 + it[0] / k, y0 + it[1] / k) }
        val now = System.currentTimeMillis()
        // steady: the corners moved less than 1.5% of the document over the last 300 ms
        history.addLast(now to quad)
        while (history.isNotEmpty() && now - history.first().first > 600) history.removeFirst()
        val old = history.firstOrNull { now - it.first >= 240 } ?: history.first()
        val diag = hypot(quad[0][0] - quad[2][0], quad[0][1] - quad[2][1]).coerceAtLeast(1.0)
        val moved = quad.indices.maxOf { hypot(quad[it][0] - old.second[it][0], quad[it][1] - old.second[it][1]) } / diag
        val steady = old === history.last() || moved < 0.015
        // area relative to the whole view (a Photo's "move closer")
        val area = f.area * (aw * ah) / (w.toDouble() * h)
        return Seen(quad, area, light(im, f.quad), steady, sharp(im, f.quad))
    }

    /** Within the quad's middle: dark, a patch of glare, or fine (the web camera's rules, core/webcam.js). */
    private fun light(im: Grey, q: List<DoubleArray>): String {
        val xs = q.map { it[0] }; val ys = q.map { it[1] }
        val mx = (xs.max() - xs.min()) * 0.08; val my = (ys.max() - ys.min()) * 0.08
        val x0 = max(0, (xs.min() + mx).toInt()); val x1 = min(im.w, (xs.max() - mx).toInt())
        val y0 = max(0, (ys.min() + my).toInt()); val y1 = min(im.h, (ys.max() - my).toInt())
        if (x1 <= x0 || y1 <= y0) return "ok"
        val hist = IntArray(256); val cs = IntArray(24); val cn = IntArray(24)
        var n = 0; var sum = 0L; var sat = 0
        for (yy in y0 until y1) {
            val cy = min(3, (yy - y0) * 4 / (y1 - y0))
            for (xx in x0 until x1) {
                val v = im.g[yy * im.w + xx]; val c = cy * 6 + min(5, (xx - x0) * 6 / (x1 - x0))
                hist[v]++; sum += v; n++; cn[c]++
                if (v >= 253) { sat++; cs[c]++ }
            }
        }
        fun pct(q: Double): Int { var a = 0; for (v in 0 until 256) { a += hist[v]; if (a >= n * q) return v }; return 255 }
        val mean = sum.toDouble() / n
        if (pct(0.95) < 85 || mean < 30) return "dark"
        val patches = (0 until 24).count { cn[it] > 0 && cs[it].toDouble() / cn[it] >= 0.5 }
        val share = sat.toDouble() / n; val white = pct(0.5) >= 228
        if (patches >= (if (white) 2 else 1) && share >= (if (white) 0.1 else 0.025)) return "glare"
        return "ok"
    }

    /**
     * Blurred by motion? Variance of the Laplacian inside the quad, against this document's best of the
     * last few looks: well under it means this frame shook. null until there is something to compare.
     */
    private fun sharp(im: Grey, q: List<DoubleArray>): Boolean? {
        val xs = q.map { it[0] }; val ys = q.map { it[1] }
        val x0 = max(1, (xs.min() + (xs.max() - xs.min()) * 0.1).toInt()); val x1 = min(im.w - 1, (xs.max() - (xs.max() - xs.min()) * 0.1).toInt())
        val y0 = max(1, (ys.min() + (ys.max() - ys.min()) * 0.1).toInt()); val y1 = min(im.h - 1, (ys.max() - (ys.max() - ys.min()) * 0.1).toInt())
        if (x1 - x0 < 8 || y1 - y0 < 8) return null
        var s = 0.0; var s2 = 0.0; var n = 0
        for (yy in y0 until y1) for (xx in x0 until x1) {
            val o = yy * im.w + xx
            val l = (4 * im.g[o] - im.g[o - 1] - im.g[o + 1] - im.g[o - im.w] - im.g[o + im.w]).toDouble()
            s += l; s2 += l * l; n++
        }
        val v = s2 / n - (s / n) * (s / n)
        sharpness.addLast(v)
        while (sharpness.size > 8) sharpness.removeFirst()
        if (sharpness.size < 3) return null
        return v >= sharpness.max() * 0.45
    }

    private fun darkAll(im: Grey): Boolean {
        var sum = 0L; var n = 0; val hist = IntArray(256)
        var i = 0
        while (i < im.g.size) { sum += im.g[i]; hist[im.g[i]]++; n++; i += 5 }
        var a = 0; var p95 = 0
        for (v in 0 until 256) { a += hist[v]; if (a >= n * 0.95) { p95 = v; break } }
        return sum.toDouble() / n < 28 && p95 < 50
    }

    /** The corners in a still, near the frame: a fresh look at a grey copy of it (`box` in the copy's pixels). */
    fun findIn(im: Grey, box: Box, shape: String): Found? {
        val ratio = when (shape) { "id1" -> 1.586; "td3" -> 1.42; else -> null }
        val x0 = max(0, (box.x - box.w * 0.15).toInt()); val y0 = max(0, (box.y - box.h * 0.15).toInt())
        val x1 = min(im.w, (box.x + box.w * 1.15).toInt()); val y1 = min(im.h, (box.y + box.h * 1.15).toInt())
        val w = x1 - x0; val h = y1 - y0
        if (w < 32 || h < 32) return null
        val g = IntArray(w * h)
        for (yy in 0 until h) System.arraycopy(im.g, (y0 + yy) * im.w + x0, g, yy * w, w)
        val f = DocFind.find(Grey(w, h, g), 0.25, ratio) ?: return null
        // a believable document: most of the frame, the right proportions
        val across = (hypot(f.quad[1][0] - f.quad[0][0], f.quad[1][1] - f.quad[0][1]) + hypot(f.quad[2][0] - f.quad[3][0], f.quad[2][1] - f.quad[3][1])) / 2
        if (across < box.w * 0.6 || abs(across / box.w - 1) > 0.25) return null
        return Found(f.quad.map { doubleArrayOf(it[0] + x0, it[1] + y0) }, f.score, f.area, f.crisp, f.ratio)
    }

    companion object {
        /** A grey copy of a bitmap, `max` on its long side. */
        fun grey(b: Bitmap, max: Int): Grey {
            val k = min(1.0, max.toDouble() / max(b.width, b.height))
            val w = max(1, (b.width * k).toInt()); val h = max(1, (b.height * k).toInt())
            val small = Bitmap.createScaledBitmap(b, w, h, true)
            val px = IntArray(w * h)
            small.getPixels(px, 0, w, 0, 0, w, h)
            if (small !== b) small.recycle()
            return Grey(w, h, IntArray(w * h) { val c = px[it]; (((c shr 16) and 0xff) * 77 + ((c shr 8) and 0xff) * 150 + (c and 0xff) * 29) shr 8 })
        }
    }
}
