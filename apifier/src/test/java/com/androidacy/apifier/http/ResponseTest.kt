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
package com.androidacy.apifier.http

import com.androidacy.apifier.http.MediaType.Companion.toMediaTypeOrNull
import com.androidacy.apifier.http.ResponseBody.Companion.asResponseBody
import com.androidacy.apifier.http.ResponseBody.Companion.toResponseBody
import java.io.File
import java.io.IOException
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.runTest
import okio.Buffer
import okio.ForwardingSource
import okio.Source
import okio.Timeout
import okio.buffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ResponseTest {

    @Test
    fun responseBuilderDefaultsEmptyBody() = runTest {
        val response = newBuilder().build()

        assertEquals(0L, response.body.contentLength())
        assertArrayEquals(ByteArray(0), response.body.bytes())
        assertEquals("", response.message)
        assertEquals(Protocol.HTTP_1_1, response.protocol)
    }

    @Test
    fun responseIsSuccessfulRange() {
        assertFalse(newBuilder().code(199).build().isSuccessful)
        assertTrue(newBuilder().code(200).build().isSuccessful)
        assertTrue(newBuilder().code(299).build().isSuccessful)
        assertFalse(newBuilder().code(300).build().isSuccessful)
    }

    @Test
    fun responseCloseClosesBody() {
        var closed = false
        val source = object : ForwardingSource(Buffer().writeUtf8("hello")) {
            override fun close() {
                closed = true
                super.close()
            }
        }.buffer()

        val response = newBuilder().body(source.asResponseBody(null, 5L)).build()
        response.close()

        assertTrue(closed)
    }

    @Test
    fun suspendBytesReadsTheWholeBody() = runTest {
        val payload = ByteArray(30) { it.toByte() }
        val response = newBuilder().body(payload.toResponseBody()).build()

        assertArrayEquals(payload, response.body.bytes())
    }

    @Test
    fun suspendStringDecodesWithTheContentTypeCharset() = runTest {
        val bytes = "héllo".toByteArray(Charsets.ISO_8859_1)
        val response = newBuilder()
            .body(bytes.toResponseBody("text/plain; charset=iso-8859-1".toMediaTypeOrNull()))
            .build()

        assertEquals("héllo", response.body.string())
    }

    @Test
    fun suspendAccessorsRunOffTheCallingThread() = runTest {
        var readThread: Thread? = null
        val source = object : ForwardingSource(Buffer().writeUtf8("hello")) {
            override fun read(sink: Buffer, byteCount: Long): Long {
                readThread = Thread.currentThread()
                return super.read(sink, byteCount)
            }
        }.buffer()
        val response = newBuilder().body(source.asResponseBody(null, 5L)).build()
        val callingThread = Thread.currentThread()

        response.body.bytes()

        assertNotEquals(callingThread, readThread)
    }

    @Test
    fun bodyIsClosedAfterASuspendRead() = runTest {
        var closed = false
        val source = object : ForwardingSource(Buffer().writeUtf8("hello")) {
            override fun close() {
                closed = true
                super.close()
            }
        }.buffer()
        val response = newBuilder().body(source.asResponseBody(null, 5L)).build()

        response.body.bytes()

        assertTrue(closed)
    }

    @Test
    fun readingTwiceFails() = runTest {
        val payload = "hello".toByteArray()
        val response = newBuilder().body(payload.toResponseBody()).build()

        response.body.bytes()
        val second = response.body.bytes()

        assertFalse("a second read replayed the already-consumed body", second.contentEquals(payload))
    }

    @Test
    fun writeToStreamsTheBodyToDisk() = runTest {
        val payload = ByteArray(5_000) { it.toByte() }
        val response = newBuilder().body(payload.toResponseBody()).build()
        val file = File.createTempFile("apifier-write-to", ".bin")

        val written = response.body.writeTo(file)

        assertEquals(payload.size.toLong(), written)
        assertArrayEquals(payload, file.readBytes())
        file.delete()
    }

    @Test
    fun writeToDoesNotBufferTheWholeBody() = runTest {
        val chunkSize = 8_192
        val payload = ByteArray(chunkSize * 3) { it.toByte() }
        val file = File.createTempFile("apifier-write-to-chunked", ".bin")
        var served = 0
        val diskLengthsBeforeLaterChunks = mutableListOf<Long>()
        val source = object : Source {
            override fun read(sink: Buffer, byteCount: Long): Long {
                if (served == payload.size / chunkSize) return -1L
                if (served > 0) diskLengthsBeforeLaterChunks.add(file.length())
                sink.write(payload, served * chunkSize, chunkSize)
                served++
                return chunkSize.toLong()
            }

            override fun timeout(): Timeout = Timeout.NONE

            override fun close() = Unit
        }.buffer()
        val response = newBuilder().body(source.asResponseBody(null, payload.size.toLong())).build()

        val written = response.body.writeTo(file)

        assertEquals(payload.size.toLong(), written)
        assertArrayEquals(payload, file.readBytes())
        assertTrue(
            "the previous chunk should already be on disk before the transfer finishes",
            diskLengthsBeforeLaterChunks.all { it > 0 }
        )
        file.delete()
    }

    @Test
    fun writeToClosesTheBody() = runTest {
        var closed = false
        val source = object : ForwardingSource(Buffer().writeUtf8("hello")) {
            override fun close() {
                closed = true
                super.close()
            }
        }.buffer()
        val response = newBuilder().body(source.asResponseBody(null, 5L)).build()
        val file = File.createTempFile("apifier-write-to-close", ".bin")

        response.body.writeTo(file)

        assertTrue(closed)
        file.delete()
    }

    @Test
    fun writeToPropagatesAFailureAndLeavesThePartialFile() = runTest {
        val firstChunk = "partial-".toByteArray()
        val failure = IOException("read failed")
        var served = false
        val source = object : Source {
            override fun read(sink: Buffer, byteCount: Long): Long {
                if (served) throw failure
                served = true
                sink.write(firstChunk)
                return firstChunk.size.toLong()
            }

            override fun timeout(): Timeout = Timeout.NONE

            override fun close() = Unit
        }.buffer()
        val response = newBuilder().body(source.asResponseBody(null, -1L)).build()
        val file = File.createTempFile("apifier-write-to-fail", ".bin")

        val thrown = try {
            response.body.writeTo(file)
            null
        } catch (e: IOException) {
            e
        }

        assertEquals(failure.message, thrown?.message)
        assertArrayEquals(firstChunk, file.readBytes())
        file.delete()
    }

    @Test
    fun readClosesTheBodyWhenBlockReturns() = runTest {
        var closed = false
        val source = object : ForwardingSource(Buffer().writeUtf8("hello")) {
            override fun close() {
                closed = true
                super.close()
            }
        }.buffer()
        val response = newBuilder().body(source.asResponseBody(null, 5L)).build()

        val result = response.body.read { it.readUtf8() }

        assertEquals("hello", result)
        assertTrue(closed)
    }

    @Test
    fun readClosesTheBodyWhenBlockThrows() = runTest {
        var closed = false
        val source = object : ForwardingSource(Buffer().writeUtf8("hello")) {
            override fun close() {
                closed = true
                super.close()
            }
        }.buffer()
        val response = newBuilder().body(source.asResponseBody(null, 5L)).build()
        val failure = IllegalStateException("block failed")

        val thrown = try {
            response.body.read<Unit> { throw failure }
            null
        } catch (e: IllegalStateException) {
            e
        }

        assertEquals(failure.message, thrown?.message)
        assertTrue(closed)
    }

    @Test
    fun readRunsOffTheCallingThread() = runTest {
        var blockThread: Thread? = null
        val response = newBuilder().body("hello".toByteArray().toResponseBody()).build()
        val callingThread = Thread.currentThread()

        response.body.read { blockThread = Thread.currentThread() }

        assertNotEquals(callingThread, blockThread)
    }

    @Test
    fun headerFallsBackToTheDefaultValue() {
        val response = newBuilder()
            .headers(Headers.headersOf("Content-Type", "text/plain"))
            .build()

        assertEquals("text/plain", response.header("content-type"))
        assertEquals("none", response.header("X-Missing", "none"))
    }

    @Test
    fun builderRequiresRequestAndCode() {
        assertEquals(
            IllegalStateException::class.java,
            runCatching { Response.Builder().code(200).build() }.exceptionOrNull()?.javaClass
        )
        assertEquals(
            IllegalStateException::class.java,
            runCatching { Response.Builder().request(request()).build() }.exceptionOrNull()?.javaClass
        )
    }

    @Test
    fun successOrThrowReturnsASuccessfulResponse() {
        val response = newBuilder().code(200).build()

        assertSame(response, response.successOrThrow())
    }

    @Test
    fun successOrThrowThrowsCarryingTheStatus() {
        val response = newBuilder().code(404).build()

        val thrown = try {
            response.successOrThrow()
            null
        } catch (e: ApifierException.HttpError) {
            e
        }

        assertEquals(404, thrown?.code)
    }

    @Test
    fun successOrThrowClosesTheBodyWhenItThrows() {
        var closed = false
        val source = object : ForwardingSource(Buffer().writeUtf8("hello")) {
            override fun close() {
                closed = true
                super.close()
            }
        }.buffer()
        val response = newBuilder().code(500).body(source.asResponseBody(null, 5L)).build()

        runCatching { response.successOrThrow() }

        assertTrue(closed)
    }

    @Test
    fun retryAfterParsesDeltaSeconds() {
        val response = newBuilder().headers(Headers.headersOf("Retry-After", "120")).build()

        assertEquals(120.seconds, response.retryAfter)
    }

    @Test
    fun retryAfterParsesAnHttpDate() {
        val target = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(90)
        val header = target.format(DateTimeFormatter.RFC_1123_DATE_TIME)
        val response = newBuilder().headers(Headers.headersOf("Retry-After", header)).build()

        val parsed = response.retryAfter

        assertTrue("expected a duration near 90s, got $parsed", parsed != null && (parsed - 90.seconds).inWholeSeconds in -2..2)
    }

    @Test
    fun retryAfterIsZeroForADateInThePast() {
        val target = ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(90)
        val header = target.format(DateTimeFormatter.RFC_1123_DATE_TIME)
        val response = newBuilder().headers(Headers.headersOf("Retry-After", header)).build()

        assertEquals(kotlin.time.Duration.ZERO, response.retryAfter)
    }

    @Test
    fun retryAfterCoercesANegativeDeltaSecondsToZero() {
        val response = newBuilder().headers(Headers.headersOf("Retry-After", "-5")).build()

        assertEquals(kotlin.time.Duration.ZERO, response.retryAfter)
    }

    @Test
    fun retryAfterIsNullWhenAbsentOrUnparseable() {
        assertNull(newBuilder().build().retryAfter)
        assertNull(newBuilder().headers(Headers.headersOf("Retry-After", "soon")).build().retryAfter)
    }

    private fun request(): Request = Request.Builder().url("https://example.com/").build()

    private fun newBuilder(): Response.Builder = Response.Builder().request(request()).code(200)
}
