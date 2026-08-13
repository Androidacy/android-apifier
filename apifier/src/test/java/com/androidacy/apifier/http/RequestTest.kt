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
import com.androidacy.apifier.http.RequestBody.Companion.asRequestBody
import com.androidacy.apifier.http.RequestBody.Companion.toRequestBody
import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class RequestTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun builderRejectsNonHttpsUrl() {
        for (url in listOf("http://example.com/x", "notaurl", "https://", "ftp://example.com")) {
            val failure = runCatching { Request.Builder().url(url).build() }.exceptionOrNull()
            assertEquals(
                "expected rejection for $url",
                IllegalArgumentException::class.java,
                failure?.javaClass
            )
        }
    }

    @Test
    fun builderParsesHostFromUrl() {
        val request = Request.Builder().url("https://Example.com:8443/a/b?q=1").build()

        assertEquals("Example.com", request.uri.host)
        assertEquals("GET", request.method)
        assertNull(request.body)
    }

    @Test
    fun requestTagRoundTrips() {
        val request = Request.Builder()
            .url("https://example.com/")
            .tag(String::class.java, "correlation-id")
            .build()

        assertEquals("correlation-id", request.tag(String::class.java))
        assertNull(request.tag(Integer::class.java))
        assertNull(Request.Builder().url("https://example.com/").build().tag(String::class.java))
    }

    @Test
    fun newBuilderCarriesEveryField() {
        val body = "payload".toRequestBody("text/plain".toMediaTypeOrNull())
        val original = Request.Builder()
            .url("https://example.com/")
            .post(body)
            .addHeader("X-A", "1")
            .tag(String::class.java, "t")
            .build()

        val copy = original.newBuilder().addHeader("X-B", "2").build()

        assertEquals("POST", copy.method)
        assertEquals(body, copy.body)
        assertEquals("1", copy.headers["X-A"])
        assertEquals("2", copy.headers["X-B"])
        assertEquals("t", copy.tag(String::class.java))
        assertNull(original.headers["X-B"])
    }

    @Test
    fun methodRejectsBodyMismatch() {
        val body = "x".toRequestBody(null)

        assertEquals(
            IllegalArgumentException::class.java,
            runCatching { Request.Builder().url("https://example.com/").method("GET", body) }
                .exceptionOrNull()?.javaClass
        )
        assertEquals(
            IllegalArgumentException::class.java,
            runCatching { Request.Builder().url("https://example.com/").method("POST", null) }
                .exceptionOrNull()?.javaClass
        )
    }

    @Test
    fun requestBodyFactoriesCarryContentTypeAndLength() {
        val type = "text/plain; charset=utf-8".toMediaTypeOrNull()

        val stringBody = "héllo".toRequestBody(type)
        assertEquals(type, stringBody.contentType())
        assertEquals(6L, stringBody.contentLength())
        assertEquals("héllo", String(writeToBytes(stringBody), Charsets.UTF_8))

        val byteBody = byteArrayOf(1, 2, 3, 4).toRequestBody("application/octet-stream".toMediaTypeOrNull())
        assertEquals("application/octet-stream", byteBody.contentType().toString())
        assertEquals(4L, byteBody.contentLength())

        val file = temporaryFolder.newFile("payload.bin").apply { writeBytes(ByteArray(37)) }
        val fileBody = file.asRequestBody("application/octet-stream".toMediaTypeOrNull())
        assertEquals(37L, fileBody.contentLength())
        assertEquals(37, writeToBytes(fileBody).size)
    }

    @Test
    fun stringBodyEncodesWithTheCharsetOfItsContentType() {
        val body = "héllo".toRequestBody("text/plain; charset=iso-8859-1".toMediaTypeOrNull())

        assertEquals(5L, body.contentLength())
        assertEquals("héllo", String(writeToBytes(body), Charsets.ISO_8859_1))
    }

    private fun writeToBytes(body: RequestBody): ByteArray = Buffer().also { body.writeTo(it) }.readByteArray()
}
