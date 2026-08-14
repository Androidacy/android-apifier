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
import kotlinx.coroutines.test.runTest
import okio.Buffer
import okio.ForwardingSource
import okio.buffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
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

    private fun request(): Request = Request.Builder().url("https://example.com/").build()

    private fun newBuilder(): Response.Builder = Response.Builder().request(request()).code(200)
}
