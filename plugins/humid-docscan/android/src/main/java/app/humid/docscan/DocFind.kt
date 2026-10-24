// Finding a document's four corners in a small grey picture: a port of
// apps/mobile/src/core/docfind.js findDocument (the same detector the app uses on imported
// photos and the web camera uses live). Plain Kotlin on a grey array, no Android, so it is
// unit tested on the JVM against the JS's answers (DocFindTest).
//
// Edges → straight lines (a Hough transform that votes along each edge's own direction) →
// the four lines that best make a document: convex, sides backed by edge along most of
// their length, the inside consistently lighter (or darker) than the outside, as large as
// the picture allows. Then each side is refitted to its own edge points.

package app.humid.docscan

import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.acos
import kotlin.math.atan2
import kotlin.math.ceil
import kotlin.math.cos
import kotlin.math.exp
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlin.math.sign

/** A grey picture: w × h bytes, row by row (0..255). */
class Grey(val w: Int, val h: Int, val g: IntArray)

class Found(val quad: List<DoubleArray>, val score: Double, val area: Double, val crisp: Double, val ratio: Double)

object DocFind {
    private const val D2R = PI / 180
    private const val NT = 180
    private val COS = DoubleArray(NT) { cos(it * D2R) }
    private val SIN = DoubleArray(NT) { sin(it * D2R) }

    /** Area-average down so the long side is at most `max`. */
    fun shrink(im: Grey, max: Int): Grey {
        val s = min(1.0, max.toDouble() / max(im.w, im.h))
        if (s == 1.0) return im
        val w = max(1, (im.w * s).roundToInt()); val h = max(1, (im.h * s).roundToInt())
        val g = IntArray(w * h)
        val fx = im.w.toDouble() / w; val fy = im.h.toDouble() / h
        for (y in 0 until h) {
            val y0 = (y * fy).toInt(); val y1 = max(y0 + 1, ((y + 1) * fy).toInt())
            for (x in 0 until w) {
                val x0 = (x * fx).toInt(); val x1 = max(x0 + 1, ((x + 1) * fx).toInt())
                var t = 0
                for (yy in y0 until y1) for (xx in x0 until x1) t += im.g[yy * im.w + xx]
                g[y * w + x] = t / ((y1 - y0) * (x1 - x0))
            }
        }
        return Grey(w, h, g)
    }

    private fun smooth(im: Grey): FloatArray {
        val w = im.w; val h = im.h
        var src = FloatArray(w * h) { im.g[it].toFloat() }
        repeat(2) {
            val out = FloatArray(w * h)
            for (y in 0 until h) {
                val ya = if (y > 0) y - 1 else 0; val yb = if (y < h - 1) y + 1 else h - 1
                for (x in 0 until w) {
                    val xa = if (x > 0) x - 1 else 0; val xb = if (x < w - 1) x + 1 else w - 1
                    out[y * w + x] = (src[ya * w + xa] + src[ya * w + x] + src[ya * w + xb] + src[y * w + xa] + src[y * w + x] + src[y * w + xb] +
                        src[yb * w + xa] + src[yb * w + x] + src[yb * w + xb]) / 9f
                }
            }
            src = out
        }
        return src
    }

    private class Line(val t: Int, val r: Int, val v: Float)
    private class ABC(val a: Double, val b: Double, val c: Double)
    private class P(val x: Double, val y: Double)
    private class Support(val cover: Double, val pts: List<P>, val lighter: Int, val hits: Int, val crisp: Double)

    private class Ctx(val w: Int, val h: Int, val s: FloatArray, val gx: FloatArray, val gy: FloatArray, val mag: FloatArray, val thr: Double, val raw: IntArray)

    private fun lines(w: Int, h: Int, gx: FloatArray, gy: FloatArray, mag: FloatArray, thr: Double): List<Line> {
        val diag = ceil(hypot(w.toDouble(), h.toDouble())).toInt(); val nr = 2 * diag + 1
        val acc = FloatArray(NT * nr)
        for (y in 2 until h - 2) for (x in 2 until w - 2) {
            val i = y * w + x; val m = mag[i]
            if (m < thr) continue
            val ux = gx[i] / m; val uy = gy[i] / m
            val sx = Math.round(ux); val sy = Math.round(uy)
            if (m < mag[i + sy * w + sx] || m < mag[i - sy * w - sx]) continue
            val t0 = Math.round(atan2(uy.toDouble(), ux.toDouble()) / D2R).toInt()
            val wgt = min(2.0, m / thr).toFloat()
            for (dt in -5..5) {
                var t = ((t0 + dt) % 360 + 360) % 360
                if (t >= 180) t -= 180
                val r = Math.round(x * COS[t] + y * SIN[t]).toInt()
                acc[t * nr + r + diag] += wgt
            }
        }
        val minV = max(10.0, min(w, h) * 0.12)
        fun get(t0: Int, r0: Int): Float {
            var t = t0; var r = r0
            if (t < 0) { t += NT; r = -r } else if (t >= NT) { t -= NT; r = -r }
            val ri = r + diag
            return if (ri < 0 || ri >= nr) 0f else acc[t * nr + ri]
        }
        val peaks = ArrayList<Line>()
        for (t in 0 until NT) for (ri in 0 until nr) {
            val v = acc[t * nr + ri]
            if (v < minV) continue
            val r = ri - diag
            var top = true
            loop@ for (dt in -3..3) for (dr in -4..4) {
                if (dt == 0 && dr == 0) continue
                val u = get(t + dt, r + dr)
                if (u > v || (u == v && (dt < 0 || (dt == 0 && dr < 0)))) { top = false; break@loop }
            }
            if (top) peaks.add(Line(t, r, v))
        }
        peaks.sortByDescending { it.v }
        return peaks.take(28)
    }

    private fun cross(p: ABC, q: ABC): P? {
        val det = p.a * q.b - q.a * p.b
        if (abs(det) < 0.2) return null
        return P((p.c * q.b - q.c * p.b) / det, (p.a * q.c - q.a * p.c) / det)
    }
    private fun abc(l: Line) = ABC(cos(l.t * D2R), sin(l.t * D2R), l.r.toDouble())
    private fun dist(a: P, b: P) = hypot(a.x - b.x, a.y - b.y)
    private fun area(q: List<P>): Double { var s = 0.0; for (i in 0 until 4) { val n = q[(i + 1) % 4]; s += q[i].x * n.y - n.x * q[i].y }; return abs(s) / 2 }

    private fun convex(q: List<P>): Boolean {
        var sg = 0.0
        for (i in 0 until 4) {
            val a = q[i]; val b = q[(i + 1) % 4]; val c = q[(i + 2) % 4]
            val z = (b.x - a.x) * (c.y - b.y) - (b.y - a.y) * (c.x - b.x)
            if (abs(z) < 1e-6) return false
            if (sg == 0.0) sg = sign(z) else if (sign(z) != sg) return false
        }
        return true
    }

    private fun angles(q: List<P>) = (0 until 4).map { i ->
        val p = q[i]; val a = q[(i + 3) % 4]; val b = q[(i + 1) % 4]
        val v1x = a.x - p.x; val v1y = a.y - p.y; val v2x = b.x - p.x; val v2y = b.y - p.y
        acos(((v1x * v2x + v1y * v2y) / (hypot(v1x, v1y) * hypot(v2x, v2y))).coerceIn(-1.0, 1.0)) / D2R
    }

    private fun support(c: Ctx, a: P, b: P, centre: P): Support {
        val len = dist(a, b)
        var nx = -(b.y - a.y) / len; var ny = (b.x - a.x) / len
        val mx = (a.x + b.x) / 2; val my = (a.y + b.y) / 2
        if (nx * (centre.x - mx) + ny * (centre.y - my) > 0) { nx = -nx; ny = -ny }
        val k = max(16, min(64, Math.round(len / 4).toInt()))
        val pts = ArrayList<P>()
        var hits = 0; var lighter = 0; var crisp = 0.0; var crispN = 0
        val cosMax = cos(25 * D2R)
        for (j in 0 until k) {
            val f = 0.06 + (0.88 * (j + 0.5)) / k
            val px = a.x + (b.x - a.x) * f; val py = a.y + (b.y - a.y) * f
            var best = 0f; var bx = 0; var by = 0
            for (d in -3..3) {
                val x = Math.round(px + nx * d).toInt(); val y = Math.round(py + ny * d).toInt()
                if (x < 1 || y < 1 || x >= c.w - 1 || y >= c.h - 1) continue
                val i = y * c.w + x; val m = c.mag[i]
                if (m <= best || abs((c.gx[i] * nx + c.gy[i] * ny) / m) < cosMax) continue
                best = m; bx = x; by = y
            }
            if (best < c.thr * 0.8) continue
            hits++
            pts.add(P(bx.toDouble(), by.toDouble()))
            fun idx(o: Int): Int { val x = min(c.w - 1, max(0, Math.round(bx + nx * o).toInt())); val y = min(c.h - 1, max(0, Math.round(by + ny * o).toInt())); return y * c.w + x }
            if (c.s[idx(-4)] > c.s[idx(4)]) lighter++
            val total = abs(c.raw[idx(-6)] - c.raw[idx(6)])
            if (total >= 16) {
                var step = 0
                for (o in -6 until 6) step = max(step, abs(c.raw[idx(o + 1)] - c.raw[idx(o)]))
                crisp += min(1.0, step.toDouble() / total); crispN++
            }
        }
        return Support(hits.toDouble() / k, pts, lighter, hits, if (crispN > 0) crisp / crispN else 0.0)
    }

    private fun fit(pts: List<P>): ABC {
        val n = pts.size
        val mx = pts.sumOf { it.x } / n; val my = pts.sumOf { it.y } / n
        var sxx = 0.0; var sxy = 0.0; var syy = 0.0
        for (p in pts) { val dx = p.x - mx; val dy = p.y - my; sxx += dx * dx; sxy += dx * dy; syy += dy * dy }
        val th = 0.5 * atan2(2 * sxy, sxx - syy)
        val a = -sin(th); val b = cos(th)
        return ABC(a, b, a * mx + b * my)
    }

    private class Cand(val q: List<P>, val score: Double, val area: Double, val sup: List<Support>, val crisp: Double, val ratio: Double)

    /** findDocument(im, { minArea, ratio }). Corners tl, tr, br, bl in im's pixels, or null. */
    fun find(im: Grey, minArea: Double = 0.08, ratio: Double? = null): Found? {
        val w = im.w; val h = im.h
        if (w < 32 || h < 32) return null
        val s = smooth(im)
        val gx = FloatArray(w * h); val gy = FloatArray(w * h); val mag = FloatArray(w * h)
        for (y in 1 until h - 1) for (x in 1 until w - 1) {
            val i = y * w + x
            val a = s[i - w - 1]; val b = s[i - w]; val c = s[i - w + 1]; val d = s[i - 1]; val f = s[i + 1]; val g = s[i + w - 1]; val k = s[i + w]; val l = s[i + w + 1]
            val xx = c + 2 * f + l - a - 2 * d - g; val yy = g + 2 * k + l - a - 2 * b - c
            gx[i] = xx; gy[i] = yy; mag[i] = hypot(xx.toDouble(), yy.toDouble()).toFloat()
        }
        val hist = IntArray(1024)
        for (m in mag) hist[min(1023, m.toInt())]++
        var acc = 0; var med = 0
        for (bkt in 0 until 1024) { acc += hist[bkt]; if (acc >= mag.size * 0.5) { med = bkt; break } }
        val thr = max(28.0, min(110.0, med * 4.0))
        val ls = lines(w, h, gx, gy, mag, thr)
        val ctx = Ctx(w, h, s, gx, gy, mag, thr, im.g)
        val horiz = ls.filter { it.t in 45..134 }.take(10)
        val vert = ls.filter { it.t !in 45..134 }.take(10)
        val cx = w / 2.0; val cy = h / 2.0
        fun yAt(l: Line) = (l.r - cx * cos(l.t * D2R)) / sin(l.t * D2R)
        fun xAt(l: Line) = (l.r - cy * sin(l.t * D2R)) / cos(l.t * D2R)
        fun between(p: Line, q: Line): Int { val d = abs(p.t - q.t) % 180; return min(d, 180 - d) }
        val margin = 0.03
        fun inside(p: P) = p.x >= -w * margin && p.x <= w * (1 + margin) && p.y >= -h * margin && p.y <= h * (1 + margin)

        fun consider(q: List<P>): Cand? {
            if (!q.all { inside(it) } || !convex(q)) return null
            val ar = area(q) / (w * h)
            if (ar < minArea) return null
            if (angles(q).any { it < 55 || it > 125 }) return null
            val lens = listOf(dist(q[0], q[1]), dist(q[1], q[2]), dist(q[2], q[3]), dist(q[3], q[0]))
            if (min(lens[0], lens[2]) / max(lens[0], lens[2]) < 0.55 || min(lens[1], lens[3]) / max(lens[1], lens[3]) < 0.55) return null
            val centre = P(q.sumOf { it.x } / 4, q.sumOf { it.y } / 4)
            val sup = (0 until 4).map { support(ctx, q[it], q[(it + 1) % 4], centre) }
            val cov = sup.map { it.cover }
            val sorted = cov.sorted()
            if (sorted[0] < 0.25 || sorted[1] < 0.45) return null
            val lean = sup.map { if (it.hits > 0) 2.0 * it.lighter / it.hits - 1 else 0.0 }
            val agree = lean.all { it > 0 } || lean.all { it < 0 }
            val polarity = if (agree) lean.minOf { abs(it) } else 0.0
            val mean = cov.sum() / 4
            var score = mean * (0.6 + 0.4 * sorted[0]) * (0.3 + 0.7 * polarity) * ar.pow(0.75)
            val r = (lens[0] + lens[2]) / (lens[1] + lens[3])
            val rr = max(r, 1 / r)
            if (ratio != null) score *= 0.4 + 0.6 * exp(-((rr / ratio - 1) / 0.12).pow(2))
            return Cand(q, score, ar, sup, sup.sumOf { it.crisp } / 4, rr)
        }

        var best: Cand? = null
        for (i in horiz.indices) for (j in i + 1 until horiz.size) {
            val a = horiz[i]; val b = horiz[j]
            if (between(a, b) > 30 || abs(yAt(a) - yAt(b)) < h * 0.12) continue
            val (top, bottom) = if (yAt(a) < yAt(b)) Pair(a, b) else Pair(b, a)
            for (k in vert.indices) for (m in k + 1 until vert.size) {
                val c = vert[k]; val d = vert[m]
                if (between(c, d) > 30 || abs(xAt(c) - xAt(d)) < w * 0.12) continue
                val (left, right) = if (xAt(c) < xAt(d)) Pair(c, d) else Pair(d, c)
                val tl = cross(abc(top), abc(left)) ?: continue
                val tr = cross(abc(top), abc(right)) ?: continue
                val br = cross(abc(bottom), abc(right)) ?: continue
                val bl = cross(abc(bottom), abc(left)) ?: continue
                val got = consider(listOf(tl, tr, br, bl)) ?: continue
                if (best == null || got.score > best!!.score) best = got
            }
        }
        var b = best ?: return null
        val sides = (0 until 4).map { i ->
            var pts = b.sup[i].pts
            if (pts.size < 8) return@map null
            var lf = fit(pts)
            pts = pts.filter { abs(lf.a * it.x + lf.b * it.y - lf.c) <= 1.5 }
            if (pts.size >= 8) lf = fit(pts)
            lf
        }
        if (sides.all { it != null }) {
            val q = listOf(cross(sides[0]!!, sides[3]!!), cross(sides[0]!!, sides[1]!!), cross(sides[2]!!, sides[1]!!), cross(sides[2]!!, sides[3]!!))
            if (q.all { it != null }) {
                val again = consider(q.map { it!! })
                if (again != null && again.score >= b.score * 0.85) b = again
            }
        }
        val quad = b.q.map { doubleArrayOf(min(w.toDouble(), max(0.0, it.x)), min(h.toDouble(), max(0.0, it.y))) }
        return Found(quad, b.score, b.area, b.crisp, b.ratio)
    }
}
