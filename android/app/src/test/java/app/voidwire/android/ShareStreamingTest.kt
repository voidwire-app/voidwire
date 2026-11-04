package app.voidwire.android

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File

/**
 * Shares are read in place from the provider when its descriptor is a seekable
 * regular file this process can open again; anything else gets the staging copy, as
 * before. The real descriptor checks run on the emulator (ShareStreamingDeviceTest).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ShareStreamingTest {
    /** Serves [file] as a file descriptor. */
    class FileProvider : ContentProvider() {
        companion object {
            var file: File? = null
        }

        override fun onCreate() = true
        override fun query(uri: Uri, p: Array<String>?, s: String?, a: Array<String>?, o: String?): Cursor? = null
        override fun getType(uri: Uri) = "application/octet-stream"
        override fun insert(uri: Uri, values: ContentValues?): Uri? = null
        override fun delete(uri: Uri, s: String?, a: Array<String>?) = 0
        override fun update(uri: Uri, v: ContentValues?, s: String?, a: Array<String>?) = 0

        override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor =
            ParcelFileDescriptor.open(file!!, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    /** Robolectric's Os calls are stubs, so the descriptor facts come from here. */
    private class FakeProbe(
        val regular: Boolean = true,
        val seekable: Boolean = true,
        val reopens: Boolean = true,
        val sameInode: Boolean = true,
    ) : FileShareStaging.FdProbe {
        var size = 0L
        override fun stat(fd: java.io.FileDescriptor) = FileShareStaging.FdInfo(regular, size, 1L, 42L)
        override fun seekEnd(fd: java.io.FileDescriptor) = if (seekable) size else -1L
        override fun rewind(fd: java.io.FileDescriptor) = if (seekable) 0L else -1L
        override fun statOpenedAgain(path: String) =
            if (reopens) FileShareStaging.FdInfo(regular, size, 1L, if (sameInode) 42L else 43L) else null
    }

    private val authority = "app.voidwire.streamtest"
    private val bytes = ByteArray(300_000) { (it % 251).toByte() }
    private val source: File = File.createTempFile("vw-stream-", ".bin").apply { writeBytes(bytes) }
    private val app get() = RuntimeEnvironment.getApplication()
    private val stagingCopy get() = File(File(app.cacheDir, "share-staging"), "movie.mkv")

    @After fun tearDown() {
        FileShareStaging.fdProbe = FileShareStaging.OsFdProbe
        FileProvider.file = null
        source.delete()
    }

    private fun stageWith(probe: FakeProbe, maxBytes: Long = FileShareStaging.MAX_FILE_BYTES): StagedShareFile {
        probe.size = bytes.size.toLong()
        FileShareStaging.fdProbe = probe
        FileProvider.file = source
        Robolectric.setupContentProvider(FileProvider::class.java, authority)
        return FileShareStaging.stage(app, Uri.parse("content://$authority/docs/movie.mkv"), maxBytes = maxBytes, disallowOwnUid = false)
    }

    @Test fun aSeekableReopenableFileIsReadInPlaceWithoutACopy() {
        val staged = stageWith(FakeProbe())
        assertTrue(staged.filePath, staged.filePath.startsWith("/proc/self/fd/"))
        assertEquals("movie.mkv", staged.displayName)
        assertEquals(bytes.size.toLong(), staged.sizeBytes)
        assertTrue(FileShareStaging.isStreamed(staged.filePath))
        assertTrue(FileShareStaging.isLive(staged.filePath))
        assertFalse("no staging copy", stagingCopy.exists())
        FileShareStaging.cleanup(staged.filePath)
        assertFalse(FileShareStaging.isStreamed(staged.filePath))
        assertFalse(FileShareStaging.isLive(staged.filePath))
        assertTrue("the shared file itself is never deleted", source.exists())
    }

    @Test fun anythingElseGetsTheStagingCopy() {
        for ((why, probe) in listOf(
            "not a regular file (pipe, socket)" to FakeProbe(regular = false),
            "can't seek" to FakeProbe(seekable = false),
            "can't be opened again" to FakeProbe(reopens = false),
            "opens as another file" to FakeProbe(sameInode = false),
        )) {
            val staged = stageWith(probe)
            assertFalse(why, staged.filePath.startsWith("/proc/"))
            assertFalse(why, FileShareStaging.isStreamed(staged.filePath))
            assertEquals(why, stagingCopy.absolutePath, staged.filePath)
            assertArrayEquals(why, bytes, File(staged.filePath).readBytes())
            assertTrue(why, FileShareStaging.isLive(staged.filePath))
            FileShareStaging.cleanup(staged.filePath)
            assertFalse(why, stagingCopy.exists())
        }
    }

    @Test fun anOversizeFileIsRefusedBeforeAnyCopy() {
        val err = org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            stageWith(FakeProbe(), maxBytes = 1000L)
        }
        assertTrue(err.message!!.contains("1 TB limit"))
        assertFalse(stagingCopy.exists())
    }

    @Test fun aProcPathFromBeforeARestartIsNeverLive() {
        assertFalse(FileShareStaging.isLive("/proc/self/fd/0"))
        FileShareStaging.cleanup("/proc/self/fd/0") // closes and deletes nothing
        assertTrue(source.exists())
    }
}
