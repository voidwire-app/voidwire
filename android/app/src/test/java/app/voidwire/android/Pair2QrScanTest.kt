package app.voidwire.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random
import kotlin.math.ceil
import kotlin.math.cos
import kotlin.math.exp
import kotlin.math.floor
import kotlin.math.roundToInt
import kotlin.math.sin

/**
 * A live pairing QR from the PC, as the phone camera sees it, decodes through
 * the scanner's own path (QrDecode.decodeLuminance on an analysis-sized
 * luminance frame). The symbol is testdata/qr/pair2-worst.matrix, which the
 * desktop's renderer test keeps identical to what the Pair window draws for
 * the largest realistic invite (testdata/qr/pair2-worst.uri).
 *
 * Camera model: the QR is 244 CSS px on a 96 dpi screen (64.6 mm), seen from
 * [distanceMm] with the frame's short side spanning 0.93 x distance (a ~50
 * degree field of view, wider than most phones, so pessimistic), slightly
 * tilted, lens-blurred, low contrast (a screen under room light) and noisy.
 */
class Pair2QrScanTest {
    private fun fixture(name: String): String =
        javaClass.getResourceAsStream("/qr/$name")!!.bufferedReader().readText().trimEnd()

    private val uri = fixture("pair2-worst.uri")
    private val modules: List<BooleanArray> =
        fixture("pair2-worst.matrix").lines().map { row -> BooleanArray(row.length) { row[it] == '1' } }

    private fun frame(w: Int, h: Int, distanceMm: Double, angleDeg: Double, seed: Long): ByteArray {
        val n = modules.size
        val qrMm = 244 * 25.4 / 96
        val ppm = h * qrMm / (0.93 * distanceMm) / n
        val c = cos(Math.toRadians(angleDeg))
        val s = sin(Math.toRadians(angleDeg))
        val f = DoubleArray(w * h)
        for (y in 0 until h) for (x in 0 until w) {
            var light = 0
            for (sy in 0..1) for (sx in 0..1) {
                val px = x + (sx + 0.5) / 2 - w / 2.0
                val py = y + (sy + 0.5) / 2 - h / 2.0
                val u = floor((c * px + s * py) / ppm + n / 2.0).toInt()
                val v = floor((-s * px + c * py) / ppm + n / 2.0).toInt()
                val dark = u in 0 until n && v in 0 until n && modules[v][u]
                if (!dark) light++
            }
            f[y * w + x] = light / 4.0
        }
        blur(f, w, h, 0.8)
        val rnd = Random(seed)
        return ByteArray(w * h) {
            (60 + 130 * f[it] + rnd.nextGaussian() * 6).roundToInt().coerceIn(0, 255).toByte()
        }
    }

    private fun blur(f: DoubleArray, w: Int, h: Int, sigma: Double) {
        val r = ceil(sigma * 3).toInt()
        val k = DoubleArray(2 * r + 1) { exp(-((it - r) * (it - r)) / (2 * sigma * sigma)) }
        val sum = k.sum()
        for (i in k.indices) k[i] /= sum
        val g = DoubleArray(w * h)
        for (y in 0 until h) for (x in 0 until w) {
            var a = 0.0
            for (i in -r..r) a += k[i + r] * f[y * w + (x + i).coerceIn(0, w - 1)]
            g[y * w + x] = a
        }
        for (y in 0 until h) for (x in 0 until w) {
            var a = 0.0
            for (i in -r..r) a += k[i + r] * g[(y + i).coerceIn(0, h - 1) * w + x]
            f[y * w + x] = a
        }
    }

    /**
     * The analyzer gets a stream of frames and needs one; requiring 9 of 10
     * per distance still catches a frame size that leaves too few pixels per
     * module (1280x720 decodes about 6 in 10 at 12 cm).
     */
    @Test
    fun liveDesktopQrDecodesAtTenAndTwelveCentimetres() {
        val w = QrDecode.FRAME_LONG
        val h = QrDecode.FRAME_SHORT
        val angles = listOf(0.0, 4.0, -7.0, 11.0, -15.0)
        for (distance in listOf(100.0, 120.0)) {
            var decoded = 0
            for (i in 0 until 10) {
                val text = QrDecode.decodeLuminance(frame(w, h, distance, angles[i % 5], i * 7919L), w, h)
                if (text != null) {
                    assertEquals(uri, text)
                    assertTrue(QrDecode.looksLikePairing(text))
                    decoded++
                }
            }
            assertTrue("$decoded of 10 frames decoded at $distance mm", decoded >= 9)
        }
    }
}
