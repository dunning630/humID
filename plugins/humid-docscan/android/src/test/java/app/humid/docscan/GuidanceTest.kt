// The Android guidance port against the shared golden vectors (tests/fixtures/guidance.json),
// the same file tests/lookstate.test.js runs the JS rules against.
//
//   ./gradlew :tauri-plugin-humid-docscan:testReleaseUnitTest      (in the generated Android project)

package app.humid.docscan

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.double
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

class GuidanceTest {
    private val golden: JsonObject by lazy {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null && !File(dir, "tests/fixtures/guidance.json").exists()) dir = dir.parentFile
        requireNotNull(dir) { "tests/fixtures/guidance.json not found above ${System.getProperty("user.dir")}" }
        Json.parseToJsonElement(File(dir, "tests/fixtures/guidance.json").readText()).jsonObject
    }

    private fun str(o: JsonObject, k: String): String? = (o[k] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content
    private fun quad(a: JsonArray): List<DoubleArray> = a.map { p -> p.jsonArray.map { it.jsonPrimitive.double }.toDoubleArray() }

    private fun measure(m: JsonObject) = Measure(
        found = m["found"]?.jsonPrimitive?.booleanOrNull ?: false,
        fit = str(m, "fit"),
        light = str(m, "light") ?: "ok",
        focus = str(m, "focus"),
        near = m["near"]?.jsonPrimitive?.booleanOrNull ?: false,
        sharp = m["sharp"]?.jsonPrimitive?.booleanOrNull,
        steady = m["steady"]?.jsonPrimitive?.booleanOrNull,
        wrong = str(m, "wrong"),
        wait = m["wait"]?.jsonPrimitive?.booleanOrNull ?: false,
    )

    @Test
    fun fit() {
        for (c in golden["fit"]!!.jsonArray.map { it.jsonObject }) {
            val f = c["frame"]!!.jsonObject
            val frame = Box(f["x"]!!.jsonPrimitive.double, f["y"]!!.jsonPrimitive.double, f["w"]!!.jsonPrimitive.double, f["h"]!!.jsonPrimitive.double)
            val ratio = (c["ratio"] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.double
            assertEquals(str(c, "name"), str(c, "key"), fitOf(quad(c["quad"]!!.jsonArray), frame, ratio))
        }
    }

    @Test
    fun runs() {
        for (r in golden["runs"]!!.jsonArray.map { it.jsonObject }) {
            val g = Guidance()
            val out = r["frames"]!!.jsonArray.map { f -> g.feed(measure(f.jsonObject["m"]!!.jsonObject), f.jsonObject["t"]!!.jsonPrimitive.long) }
            for (e in r["expect"]!!.jsonArray.map { it.jsonObject }) {
                val i = e["i"]!!.jsonPrimitive.long.toInt()
                val got = out[i]
                val name = "${str(r, "name")} / frame $i"
                for ((k, v) in e) {
                    when (k) {
                        "i" -> {}
                        "state" -> assertEquals("$name state", (v as JsonPrimitive).content, got.state)
                        "key" -> assertEquals("$name key", if (v is JsonNull) null else (v as JsonPrimitive).content, got.key)
                        "fire" -> assertEquals("$name fire", v.jsonPrimitive.booleanOrNull, got.fire)
                        "aligned" -> assertEquals("$name aligned", v.jsonPrimitive.booleanOrNull, got.aligned)
                        "progress" -> assertEquals("$name progress", v.jsonPrimitive.double, got.progress, 1e-9)
                        else -> error("unknown field $k")
                    }
                }
            }
        }
    }

    @Test
    fun focusingNeverWithoutRealAutofocus() {
        val g = Guidance()
        var t = 0L
        while (t < 3000) {
            for (focus in listOf(null, "focused")) {
                val l = g.feed(Measure(found = true, focus = focus, steady = t % 400 != 0L, sharp = t % 700 != 0L), t)
                assert(l.state != "focusing") { "t=$t focus=$focus" }
            }
            t += 100
        }
    }
}
