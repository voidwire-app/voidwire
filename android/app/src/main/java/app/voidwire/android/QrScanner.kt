package app.voidwire.android

import android.util.Size
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.AspectRatioStrategy
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.compose.ui.platform.LocalLifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Camera preview + QR decoding with CameraX and ZXing core: no Google Play
 * services, no network, frames never leave the analyzer. Calls [onResult]
 * once with the first QR text that looks like a pairing link.
 */
@Suppress("DEPRECATION") // LocalLifecycleOwner moved to lifecycle-runtime-compose
@Composable
fun QrScanner(modifier: Modifier = Modifier, onResult: (String) -> Unit) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val done = remember { AtomicBoolean(false) }
    val previewView = remember { PreviewView(context) }
    val latest = rememberUpdatedState(onResult)

    DisposableEffect(owner) {
        val executor = Executors.newSingleThreadExecutor()
        val future = ProcessCameraProvider.getInstance(context)
        // The provider can arrive after the screen left (back pressed, or a
        // font/size change recreated the activity): binding then throws
        // "LifecycleCamera with destroyed lifecycle" and crashes the app.
        var disposed = false
        future.addListener({
            if (disposed || owner.lifecycle.currentState == Lifecycle.State.DESTROYED) return@addListener
            val provider = future.get()
            val preview = Preview.Builder().build().also { it.setSurfaceProvider(previewView.surfaceProvider) }
            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(
                    ResolutionSelector.Builder()
                        .setAspectRatioStrategy(AspectRatioStrategy.RATIO_16_9_FALLBACK_AUTO_STRATEGY)
                        .setResolutionStrategy(
                            ResolutionStrategy(
                                Size(QrDecode.FRAME_LONG, QrDecode.FRAME_SHORT),
                                ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER,
                            ),
                        )
                        .build(),
                )
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            analysis.setAnalyzer(executor) { image ->
                val text = image.use { QrDecode.decode(it) }
                if (text != null && QrDecode.looksLikePairing(text) && done.compareAndSet(false, true)) {
                    ContextCompat.getMainExecutor(context).execute { latest.value(text) }
                }
            }
            provider.unbindAll()
            provider.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
        }, ContextCompat.getMainExecutor(context))
        onDispose {
            disposed = true
            if (future.isDone) future.get().unbindAll()
            executor.shutdown()
        }
    }
    AndroidView(factory = { previewView }, modifier = modifier)
}

object QrDecode {
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
    )

    /**
     * Analysis frame size. A pairing QR is dense (version 13-17, up to 85
     * modules) and the phone can't focus closer than about 10 cm, so the
     * frame needs ~7 pixels per module there: 1280x720 gave under 5 and
     * missed live codes (Pair2QrScanTest). Only while the scan screen is open.
     */
    const val FRAME_LONG = 1920
    const val FRAME_SHORT = 1080

    fun looksLikePairing(text: String): Boolean = text.startsWith("voidwire:pair?")

    /** Luminance (Y) plane of a YUV_420_888 frame → QR text, or null. */
    fun decode(image: ImageProxy): String? {
        val plane = image.planes[0]
        val w = image.width
        val h = image.height
        val buf = plane.buffer
        val rowStride = plane.rowStride
        val y = ByteArray(w * h)
        for (row in 0 until h) {
            buf.position(row * rowStride)
            buf.get(y, row * w, w)
        }
        return decodeLuminance(y, w, h)
    }

    fun decodeLuminance(y: ByteArray, w: Int, h: Int): String? {
        val source = PlanarYUVLuminanceSource(y, w, h, 0, 0, w, h, false)
        return try {
            QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), hints).text
        } catch (e: NotFoundException) {
            null
        } catch (e: com.google.zxing.ReaderException) {
            null
        }
    }
}
