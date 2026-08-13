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
import java.io.File
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger
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
    fun lengthFromBodyContentLength() {
        val file = tempFile("hello streaming world")
        val fileProvider = StreamingUploadProvider(file.asRequestBody(), null)
        assertEquals(file.length(), fileProvider.length)

        val unknownLength = InstrumentedBody(-1L, CountingSource(0))
        val chunkedProvider = StreamingUploadProvider(unknownLength, null)
        assertEquals(-1L, chunkedProvider.length)
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
    fun progressResetsOnRewind() {
        val body = InstrumentedBody(50L, CountingSource(50L))
        val progress = mutableListOf<Pair<Long, Long>>()
        val provider = StreamingUploadProvider(body) { sent, total -> progress.add(sent to total) }
        val sink = RecordingSink()

        provider.read(sink, ByteBuffer.allocate(16))
        provider.read(sink, ByteBuffer.allocate(16))
        assertTrue(progress.last().first > 0)

        provider.rewind(sink)

        assertEquals(0L to 50L, progress.last())
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

        override fun onReadSucceeded(finalChunk: Boolean) {
            readSucceededCalls += finalChunk
        }

        override fun onReadError(exception: Exception) {
            throw exception
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

    private class InstrumentedBody(private val length: Long, private val source: Source) : RequestBody() {
        var writeToCalled = false

        override fun contentType(): MediaType? = null

        override fun contentLength(): Long = length

        override fun writeTo(sink: BufferedSink) {
            writeToCalled = true
        }

        override fun pullSource(): Source = source
    }

    /** A file-shaped part whose pull source reports how many parts are concurrently mid-stream. */
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

        override fun pullSource(): Source = object : Source {
            private var offset = 0
            private var opened = false
            private var closed = false

            override fun read(sink: Buffer, byteCount: Long): Long {
                if (!opened) {
                    opened = true
                    peakOpen.updateAndGet { maxOf(it, openCounter.incrementAndGet()) }
                }
                if (offset >= bytes.size) return -1L
                val n = minOf(byteCount, (bytes.size - offset).toLong()).toInt()
                sink.write(bytes, offset, n)
                offset += n
                return n.toLong()
            }

            override fun timeout(): Timeout = Timeout.NONE

            override fun close() {
                if (opened && !closed) {
                    closed = true
                    openCounter.decrementAndGet()
                }
            }
        }
    }
}
