package app.voidwire.android

import android.util.Size
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
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
        future.addListener({
            val provider = future.get()
            val preview = Preview.Builder().build().also { it.setSurfaceProvider(previewView.surfaceProvider) }
            @Suppress("DEPRECATION")
            val analysis = ImageAnalysis.Builder()
                .setTargetResolution(Size(1280, 720))
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
