/*
 * Copyright 2025 Androidacy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.androidacy.apifier.client

import com.androidacy.apifier.http.MediaType
import com.androidacy.apifier.http.MultipartBody
import com.androidacy.apifier.http.RequestBody
import com.androidacy.apifier.http.RequestBody.Companion.asRequestBody
import com.androidacy.apifier.http.RequestBody.Companion.toRequestBody
import com.androidacy.apifier.progress.Progress
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import okio.Buffer
import okio.BufferedSink
import okio.Source
import okio.Timeout
import org.chromium.net.UploadDataSink
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class StreamingUploadProviderTest {

    private val tempFiles = mutableListOf<File>()

    @After
    fun cleanup() {
        tempFiles.forEach { it.delete() }
    }

    @Test
    fun neverMaterializesMoreThanOneChunk() {
        val chunkSize = 16
        val totalLength = 100L
        val source = CountingSource(totalLength)
        val body = InstrumentedBody(totalLength, source)
        val provider = StreamingUploadProvider(body, null)
        val sink = RecordingSink()

        val expectedReads = 7 // ceil(100 / 16)
        repeat(expectedReads) {
            provider.read(sink, ByteBuffer.allocate(chunkSize))
        }

        assertFalse("writeTo must never run when pullSource streams", body.writeToCalled)
        assertTrue("expected more than one read", source.producedPerCall.size > 1)
        source.producedPerCall.forEach { produced ->
            assertTrue("a single read produced $produced > chunk size $chunkSize", produced <= chunkSize)
        }
        assertEquals(totalLength, source.producedPerCall.sum())
    }

    @Test
    fun earlyExhaustionOnKnownLengthBodySurfacesReadError() {
        // Advertises 50 bytes but its source only ever has 20: a file truncated after
        // contentLength() was read, or a body that simply over-reports.
        val body = InstrumentedBody(50L, CountingSource(20L))
        val provider = StreamingUploadProvider(body, null)
        val sink = RecordingSink()

        provider.read(sink, ByteBuffer.allocate(16)) // 16 of 20
        provider.read(sink, ByteBuffer.allocate(16)) // remaining 4
        provider.read(sink, ByteBuffer.allocate(16)) // source now exhausted, 30 bytes short

        assertEquals(listOf(false, false), sink.readSucceededCalls)
        assertNotNull("expected a read error instead of a silent zero-byte success", sink.readError)
        assertTrue(sink.readError?.message.orEmpty().contains("20 of 50"))
    }

    @Test
    fun fullyDeliveredKnownLengthBodySucceedsOnFinalExhaustedRead() {
        val body = InstrumentedBody(32L, CountingSource(32L))
        val provider = StreamingUploadProvider(body, null)
        val sink = RecordingSink()

        provider.read(sink, ByteBuffer.allocate(16))
        provider.read(sink, ByteBuffer.allocate(16))
        provider.read(sink, ByteBuffer.allocate(16)) // source now exhausted, all 32 bytes already delivered

        assertNull("a body that delivered its full declared length must not read-error", sink.readError)
        assertEquals(listOf(false, false, false), sink.readSucceededCalls)
    }

    @Test
    fun chunkedSignalsFinalChunk() {
        val source = CountingSource(40L)
        val body = InstrumentedBody(-1L, source)
        val provider = StreamingUploadProvider(body, null)
        val sink = RecordingSink()

        var reads = 0
        while (sink.readSucceededCalls.lastOrNull() != true) {
            provider.read(sink, ByteBuffer.allocate(16))
            reads++
            check(reads < 100) { "runaway chunked read loop" }
        }

        // 16, 16, the trailing 8, then an exhausted 0-byte read that signals the final chunk.
        assertEquals(listOf(false, false, false, true), sink.readSucceededCalls)
    }

    @Test
    fun rewindReopensAndReplays() {
        val content = "the quick brown fox jumps over the lazy dog"
        val file = tempFile(content)
        val provider = StreamingUploadProvider(file.asRequestBody(), null)
        val sink = RecordingSink()

        val firstPass = readAll(provider, sink, content.length)
        provider.rewind(sink)
        assertTrue(sink.rewindSucceeded)
        assertNull(sink.rewindError)
        val secondPass = readAll(provider, sink, content.length)

        assertArrayEquals(content.toByteArray(), firstPass)
        assertArrayEquals(content.toByteArray(), secondPass)
    }

    @Test
    fun rewindOnChunkedBodyFails() {
        val body = InstrumentedBody(-1L, CountingSource(20L))
        val provider = StreamingUploadProvider(body, null)
        val sink = RecordingSink()

        provider.rewind(sink)

        assertFalse(sink.rewindSucceeded)
        assertNotNull(sink.rewindError)
    }

    @Test
    fun progressResetsOnRewind() = runTest {
        val body = InstrumentedBody(50L, CountingSource(50L))
        val (progress, collected) = collectingSink(this)
        val provider = StreamingUploadProvider(body, progress)
        val sink = RecordingSink()

        provider.read(sink, ByteBuffer.allocate(16))
        provider.read(sink, ByteBuffer.allocate(16))
        assertTrue(collected.last().bytesTransferred > 0)

        provider.rewind(sink)

        assertEquals(0L to 50L, collected.last().let { it.bytesTransferred to it.contentLength })
    }

    /** Production change that fails this: resetting the running total per read instead of accumulating it. */
    @Test
    fun uploadSinkReceivesMonotonicTotals() = runTest {
        val body = InstrumentedBody(48L, CountingSource(48L))
        val (progress, collected) = collectingSink(this)
        val provider = StreamingUploadProvider(body, progress)
        val sink = RecordingSink()

        repeat(3) { provider.read(sink, ByteBuffer.allocate(16)) }

        assertEquals(listOf(16L, 32L, 48L), collected.map { it.bytesTransferred })
    }

    @Test
    fun bytesSentReportedSeparatelyFromProgress() {
        val body = InstrumentedBody(32L, CountingSource(32L))
        val sent = mutableListOf<Long>()
        val provider = StreamingUploadProvider(body, null) { sent += it }
        val sink = RecordingSink()

        repeat(2) { provider.read(sink, ByteBuffer.allocate(16)) }

        assertEquals(listOf(16L, 32L), sent)
    }

    /** Production change that fails this: emitting upload progress regardless of streamsFromDisk. */
    @Test
    fun inMemoryRequestBodyReportsNoUploadProgress() = runTest {
        val body = "{}".toRequestBody(null)
        val (progress, collected) = collectingSink(this)
        val provider = StreamingUploadProvider(body, progress)
        val sink = RecordingSink()

        provider.read(sink, ByteBuffer.allocate(16))

        assertTrue("an in-memory body must not report upload progress", collected.isEmpty())
    }

    /** Production change that fails this: failing to propagate streamsFromDisk through MultipartBody. */
    @Test
    fun multipartWithAFilePartReportsUploadProgress() = runTest {
        val file = tempFile("multipart file part payload")
        val multipart = MultipartBody.Builder()
            .addFormDataPart("file", file.name, file.asRequestBody())
            .build()
        val (progress, collected) = collectingSink(this)
        val provider = StreamingUploadProvider(multipart, progress)
        val sink = RecordingSink()
        val chunkSize = 8

        // A known content length never sets the finalChunk flag (that only applies to chunked
        // bodies), so the read count is computed from the length instead of read()'s own signal.
        val reads = ((multipart.contentLength() + chunkSize - 1) / chunkSize).toInt()
        repeat(reads) { provider.read(sink, ByteBuffer.allocate(chunkSize)) }

        assertTrue("a multipart body with a file part must report upload progress", collected.isNotEmpty())
    }

    /** Production change that fails this: replacing tryEmit with a suspending emit. */
    @Test
    fun progressEmissionNeverSuspendsTheTransport() {
        val body = InstrumentedBody(32L, CountingSource(32L))
        // No collector ever drains this, and its buffer holds only one value, so a second
        // emission has nowhere to go; a suspending emit would block the calling thread forever.
        val sink = MutableSharedFlow<Progress>(extraBufferCapacity = 1)
        val provider = StreamingUploadProvider(body, sink)
        val recordingSink = RecordingSink()

        val elapsedMs = measureMillis { repeat(2) { provider.read(recordingSink, ByteBuffer.allocate(16)) } }

        assertTrue("read() took ${elapsedMs}ms; tryEmit must never block the reading thread", elapsedMs < 1_000)
    }

    private fun measureMillis(block: () -> Unit): Long {
        val start = System.nanoTime()
        block()
        return (System.nanoTime() - start) / 1_000_000
    }

    /**
     * Registers a live collector before returning, matching how a caller following the
     * documented `extraBufferCapacity > 0` shape actually receives emissions: a
     * default-shaped flow drops every `tryEmit` even with a collector attached, since its
     * zero-length buffer has no room for one before the collector re-suspends to receive it.
     */
    private fun collectingSink(scope: kotlinx.coroutines.test.TestScope): Pair<MutableSharedFlow<Progress>, List<Progress>> {
        val sink = MutableSharedFlow<Progress>(extraBufferCapacity = 8)
        val collected = mutableListOf<Progress>()
        val collectorScope = CoroutineScope(UnconfinedTestDispatcher(scope.testScheduler))
        collectorScope.launch { sink.collect { collected += it } }
        return sink to collected
    }

    private fun readAll(provider: StreamingUploadProvider, sink: RecordingSink, expectedLength: Int): ByteArray {
        val out = Buffer()
        while (out.size < expectedLength) {
            val buffer = ByteBuffer.allocate(8)
            provider.read(sink, buffer)
            buffer.flip()
            out.write(buffer)
        }
        return out.readByteArray()
    }

    private fun tempFile(content: String): File =
        File.createTempFile("streaming-upload-test", ".txt").also {
            it.writeText(content)
            tempFiles += it
        }

    private class RecordingSink : UploadDataSink() {
        val readSucceededCalls = mutableListOf<Boolean>()
        var rewindSucceeded = false
        var rewindError: Exception? = null
        var readError: Exception? = null

        override fun onReadSucceeded(finalChunk: Boolean) {
            readSucceededCalls += finalChunk
        }

        override fun onReadError(exception: Exception) {
            readError = exception
        }

        override fun onRewindSucceeded() {
            rewindSucceeded = true
        }

        override fun onRewindError(exception: Exception) {
            rewindError = exception
        }
    }

    /** Produces up to [totalLength] bytes, capping every single read at what was requested. */
    private class CountingSource(private val totalLength: Long) : Source {
        val producedPerCall = mutableListOf<Long>()
        private var remaining = totalLength

        override fun read(sink: Buffer, byteCount: Long): Long {
            if (remaining <= 0L) return -1L
            val n = minOf(byteCount, remaining)
            sink.write(ByteArray(n.toInt()))
            remaining -= n
            producedPerCall += n
            return n
        }

        override fun timeout(): Timeout = Timeout.NONE

        override fun close() = Unit
    }

    private class InstrumentedBody(
        private val length: Long,
        private val source: Source,
        override val streamsFromDisk: Boolean = true
    ) : RequestBody() {
        var writeToCalled = false

        override fun contentType(): MediaType? = null

        override fun contentLength(): Long = length

        override fun writeTo(sink: BufferedSink) {
            writeToCalled = true
        }

        override fun pullSource(): Source = source
    }

    /**
     * A file-shaped part that counts as open from the moment [pullSource] is called, not from
     * its first [Source.read]: eager opening at [pullSource] time is exactly the defect this
     * counts, and a tracker keyed off the first read cannot see it, since by the time anything
     * reads a part, an eager caller has already opened every part there is.
     */
    private class TrackingBody(
        private val bytes: ByteArray,
        private val openCounter: AtomicInteger,
        private val peakOpen: AtomicInteger
    ) : RequestBody() {

        override fun contentType(): MediaType? = null

        override fun contentLength(): Long = bytes.size.toLong()

        override fun writeTo(sink: BufferedSink) {
            sink.write(bytes)
        }

        override fun pullSource(): Source {
            peakOpen.updateAndGet { maxOf(it, openCounter.incrementAndGet()) }
            return object : Source {
                private var offset = 0
                private var closed = false

                override fun read(sink: Buffer, byteCount: Long): Long {
                    if (offset >= bytes.size) return -1L
                    val n = minOf(byteCount, (bytes.size - offset).toLong()).toInt()
                    sink.write(bytes, offset, n)
                    offset += n
                    return n.toLong()
                }

                override fun timeout(): Timeout = Timeout.NONE

                override fun close() {
                    if (!closed) {
                        closed = true
                        openCounter.decrementAndGet()
                    }
                }
            }
        }
    }

    @Test
    fun multipartStreamsPartByPart() {
        val openCounter = AtomicInteger(0)
        val peakOpen = AtomicInteger(0)
        val partA = TrackingBody(ByteArray(30) { 'a'.code.toByte() }, openCounter, peakOpen)
        val partB = TrackingBody(ByteArray(30) { 'b'.code.toByte() }, openCounter, peakOpen)
        val multipart = MultipartBody.Builder()
            .addFormDataPart("a", "a.bin", partA)
            .addFormDataPart("b", "b.bin", partB)
            .build()

        val source = multipart.pullSource()
        val buffer = Buffer()
        while (source.read(buffer, 8) != -1L) {
            buffer.clear()
        }

        assertTrue("more than one part must never be open at once, peak was ${peakOpen.get()}", peakOpen.get() <= 1)
    }

    @Test
    fun multipartLeavesEarlierPartsClosedWhenALaterPartFailsToOpen() {
        val openCounter = AtomicInteger(0)
        val peakOpen = AtomicInteger(0)
        val partA = TrackingBody(ByteArray(10) { 'a'.code.toByte() }, openCounter, peakOpen)
        val failingPart = object : RequestBody() {
            override fun contentType(): MediaType? = null

            override fun contentLength(): Long = 10L

            override fun writeTo(sink: BufferedSink) = throw UnsupportedOperationException()

            override fun pullSource(): Source = throw IOException("part source unavailable")
        }
        val multipart = MultipartBody.Builder()
            .addFormDataPart("a", "a.bin", partA)
            .addFormDataPart("b", "b.bin", failingPart)
            .build()

        val source = multipart.pullSource()
        val buffer = Buffer()
        val thrown = try {
            while (source.read(buffer, 8) != -1L) buffer.clear()
            null
        } catch (e: IOException) {
            e
        }

        assertNotNull("expected the failing part's pullSource to propagate", thrown)
        assertEquals("part A's source must already be closed, not stranded open", 0, openCounter.get())
    }
}
