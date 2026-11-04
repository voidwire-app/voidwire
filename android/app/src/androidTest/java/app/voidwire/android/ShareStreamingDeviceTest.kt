package app.voidwire.android

import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** The real descriptor checks behind in-place shares (JVM tests fake them: ShareStreamingTest). */
@RunWith(AndroidJUnit4::class)
class ShareStreamingDeviceTest {
    private val bytes = ByteArray(700_000) { (it % 253).toByte() }

    @Test fun aRegularFileStreamsAndReopensToTheSameBytes() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val f = File(ctx.cacheDir, "stream-device-test.bin").apply { writeBytes(bytes) }
        try {
            ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
                val s = FileShareStaging.streamSourceOf(pfd)
                assertNotNull("a regular file streams", s)
                assertEquals("/proc/self/fd/${pfd.fd}", s!!.path)
                assertEquals(bytes.size.toLong(), s.sizeBytes)
                // Core opens the path for every attempt: twice, same bytes, own offsets.
                assertArrayEquals(bytes, File(s.path).readBytes())
                assertArrayEquals(bytes, File(s.path).readBytes())
                // The check left the descriptor at 0, so a copy would read it all.
                assertArrayEquals(bytes, ParcelFileDescriptor.AutoCloseInputStream(pfd.dup()).use { it.readBytes() })
                assertNull("over the cap", FileShareStaging.streamSourceOf(pfd, maxBytes = 1000L))
            }
        } finally {
            f.delete()
        }
    }

    @Test fun aPipeNeedsTheCopy() {
        val (read, write) = ParcelFileDescriptor.createPipe()
        read.use { r -> write.use { assertNull("a pipe can't seek", FileShareStaging.streamSourceOf(r)) } }
    }
}
