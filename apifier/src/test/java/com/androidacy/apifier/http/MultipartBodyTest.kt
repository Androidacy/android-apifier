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
import com.androidacy.apifier.http.RequestBody.Companion.toRequestBody
import okio.Buffer
import okio.BufferedSink
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MultipartBodyTest {

    @Test
    fun multipartFramingIsWellFormed() {
        val body = twoPartBody()
        val written = String(writeToBytes(body), Charsets.UTF_8)
        val boundary = body.boundary

        val expected = "--$boundary\r\n" +
            "Content-Disposition: form-data; name=\"field\"\r\n" +
            "Content-Type: text/plain\r\n" +
            "\r\n" +
            "value\r\n" +
            "--$boundary\r\n" +
            "Content-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n" +
            "Content-Type: application/octet-stream\r\n" +
            "\r\n" +
            "0123\r\n" +
            "--$boundary--\r\n"

        assertEquals(expected, written)
        assertEquals("multipart/form-data; boundary=$boundary", body.contentType().toString())
    }

    @Test
    fun partWithoutContentTypeOmitsTheHeader() {
        val body = MultipartBody.Builder()
            .addFormDataPart("field", null, "value".toRequestBody(null))
            .build()

        val written = String(writeToBytes(body), Charsets.UTF_8)

        assertTrue(written, !written.contains("Content-Type: ", ignoreCase = false))
        assertTrue(written, written.contains("Content-Disposition: form-data; name=\"field\"\r\n\r\nvalue"))
    }

    @Test
    fun multipartContentLengthExactOrMinusOne() {
        val body = twoPartBody()

        assertEquals(writeToBytes(body).size.toLong(), body.contentLength())

        val unknownLengthPart = object : RequestBody() {
            override fun contentType(): MediaType? = null

            override fun writeTo(sink: BufferedSink) {
                sink.writeUtf8("streamed")
            }
        }
        val withUnknown = MultipartBody.Builder()
            .addFormDataPart("field", "value")
            .addFormDataPart("stream", null, unknownLengthPart)
            .build()

        assertEquals(-1L, withUnknown.contentLength())
    }

    @Test
    fun multipartWriteToIsReplayable() {
        val body = twoPartBody()

        assertArrayEquals(writeToBytes(body), writeToBytes(body))
    }

    @Test
    fun formDataNameAndFilenameAreQuotedSafely() {
        val body = MultipartBody.Builder()
            .addFormDataPart("na\"me", "a\r\nb.txt", "v".toRequestBody(null))
            .build()

        val written = String(writeToBytes(body), Charsets.UTF_8)

        assertTrue(written, written.contains("name=\"na%22me\"; filename=\"a%0D%0Ab.txt\""))
    }

    private fun twoPartBody(): MultipartBody = MultipartBody.Builder()
        .setType(MultipartBody.FORM)
        .addFormDataPart("field", null, "value".toRequestBody("text/plain".toMediaTypeOrNull()))
        .addFormDataPart("file", "a.bin", "0123".toRequestBody("application/octet-stream".toMediaTypeOrNull()))
        .build()

    private fun writeToBytes(body: RequestBody): ByteArray = Buffer().also { body.writeTo(it) }.readByteArray()
}
