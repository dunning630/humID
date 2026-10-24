// The Kotlin detector (DocFind.kt) finds the same corners as the app's own
// (apps/mobile/src/core/docfind.js) on the camera fixtures: tests/fixtures/docfind-golden.json
// holds the JS's answers on small grey copies of tests/fixtures/id/guide/*.mjpeg, made by
// tools/docfind-golden.mjs. Corners must agree within 1.5% of the picture's diagonal.

package app.humid.docscan

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.double
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Base64
import kotlin.math.hypot

class DocFindTest {
    private fun root(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null && !File(dir, "tests/fixtures/docfind-golden.json").exists()) dir = dir.parentFile
        return requireNotNull(dir) { "tests/fixtures/docfind-golden.json not found" }
    }

    @Test
    fun sameCornersAsTheApp() {
        val cases = Json.parseToJsonElement(File(root(), "tests/fixtures/docfind-golden.json").readText()).jsonObject["cases"]!!.jsonArray
        assertTrue(cases.size >= 5)
        for (c in cases.map { it.jsonObject }) {
            val name = c["name"]!!.jsonPrimitive.content
            val w = c["w"]!!.jsonPrimitive.int; val h = c["h"]!!.jsonPrimitive.int
            val bytes = Base64.getDecoder().decode(c["grey"]!!.jsonPrimitive.content)
            val im = Grey(w, h, IntArray(w * h) { bytes[it].toInt() and 0xff })
            val ratio = (c["ratio"] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it !is JsonNull }?.double
            val minArea = c["minArea"]!!.jsonPrimitive.double
            val got = DocFind.find(im, minArea, ratio)
            val want = c["quad"]
            if (want == null || want is JsonNull) { assertNull(name, got); continue }
            assertNotNull(name, got)
            val diag = hypot(w.toDouble(), h.toDouble())
            for ((i, p) in want.jsonArray.withIndex()) {
                val x = p.jsonArray[0].jsonPrimitive.double; val y = p.jsonArray[1].jsonPrimitive.double
                val off = hypot(got!!.quad[i][0] - x, got.quad[i][1] - y) / diag
                assertTrue("$name corner $i off by ${"%.2f".format(off * 100)}%", off < 0.015)
            }
            assertEquals("$name ratio", c["r"]!!.jsonPrimitive.double, got!!.ratio, 0.05)
        }
    }
}
