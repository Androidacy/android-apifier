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

import com.androidacy.apifier.http.Protocol
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ResponseAssemblyTest {

    @Test
    fun stripsEncodingHeadersWhenCronetDecoded() {
        val assembled = ResponseAssembly.assemble(
            headers = listOf(
                "Content-Type" to "text/plain",
                "Content-Encoding" to "gzip",
                "Content-Length" to "120"
            ),
            statusCode = 200,
            negotiatedProtocol = "h2",
            method = "GET"
        )

        assertTrue(assembled.bodyDecodedByCronet)
        assertEquals(listOf("Content-Type" to "text/plain"), assembled.headers)
        assertEquals("text/plain", assembled.contentType)
        assertEquals(-1L, assembled.contentLength)
    }

    @Test
    fun keepsHeadersForUnhandledEncoding() {
        val assembled = ResponseAssembly.assemble(
            headers = listOf(
                "Content-Encoding" to "myenc",
                "Content-Length" to "120"
            ),
            statusCode = 200,
            negotiatedProtocol = "http/1.1",
            method = "GET"
        )

        assertFalse(assembled.bodyDecodedByCronet)
        assertEquals(
            listOf("Content-Encoding" to "myenc", "Content-Length" to "120"),
            assembled.headers
        )
        assertEquals(120L, assembled.contentLength)
    }

    @Test
    fun multiValueEncodingListHandled() {
        val allHandled = ResponseAssembly.assemble(
            headers = listOf("Content-Encoding" to "gzip, br"),
            statusCode = 200,
            negotiatedProtocol = "h2",
            method = "GET"
        )
        assertTrue(allHandled.bodyDecodedByCronet)
        assertEquals(emptyList<Pair<String, String>>(), allHandled.headers)

        val mixed = ResponseAssembly.assemble(
            headers = listOf("Content-Encoding" to "gzip, myenc"),
            statusCode = 200,
            negotiatedProtocol = "h2",
            method = "GET"
        )
        assertFalse(mixed.bodyDecodedByCronet)
        assertEquals(listOf("Content-Encoding" to "gzip, myenc"), mixed.headers)
    }

    @Test
    fun headContentLengthIsMinusOne() {
        val assembled = ResponseAssembly.assemble(
            headers = listOf("Content-Length" to "500"),
            statusCode = 200,
            negotiatedProtocol = "h2",
            method = "HEAD"
        )

        assertFalse(assembled.bodyDecodedByCronet)
        assertEquals(-1L, assembled.contentLength)
        assertEquals(listOf("Content-Length" to "500"), assembled.headers)
    }

    @Test
    fun bodylessStatusesIgnoreContentLength() {
        for (status in listOf(204, 304)) {
            val assembled = ResponseAssembly.assemble(
                headers = listOf("Content-Length" to "500"),
                statusCode = status,
                negotiatedProtocol = "h2",
                method = "GET"
            )

            assertTrue("status $status", assembled.bodyless)
            assertEquals("status $status", -1L, assembled.contentLength)
        }

        val ok = ResponseAssembly.assemble(
            headers = listOf("Content-Length" to "500"),
            statusCode = 200,
            negotiatedProtocol = "h2",
            method = "GET"
        )
        assertFalse(ok.bodyless)
        assertEquals(500L, ok.contentLength)
    }

    @Test
    fun protocolMappingMatchesNegotiatedString() {
        val cases = mapOf(
            "h3" to Protocol.QUIC,
            "quic/1+spdy/3" to Protocol.QUIC,
            "h2" to Protocol.HTTP_2,
            "http/1.1" to Protocol.HTTP_1_1,
            "unknown" to Protocol.HTTP_1_0
        )
        for ((negotiated, expected) in cases) {
            val assembled = ResponseAssembly.assemble(
                headers = emptyList(),
                statusCode = 200,
                negotiatedProtocol = negotiated,
                method = "GET"
            )
            assertEquals(negotiated, expected, assembled.protocol)
        }
    }

    @Test
    fun lastDuplicateHeaderValueWins() {
        val assembled = ResponseAssembly.assemble(
            headers = listOf(
                "content-type" to "text/plain",
                "Content-Type" to "application/json",
                "Content-Length" to "1",
                "content-length" to "42"
            ),
            statusCode = 200,
            negotiatedProtocol = "h2",
            method = "GET"
        )

        assertEquals("application/json", assembled.contentType)
        assertEquals(42L, assembled.contentLength)
        assertEquals(4, assembled.headers.size)
    }

    @Test
    fun unparsableContentLengthIsMinusOne() {
        val assembled = ResponseAssembly.assemble(
            headers = listOf("Content-Length" to "not-a-number"),
            statusCode = 200,
            negotiatedProtocol = "h2",
            method = "GET"
        )

        assertEquals(-1L, assembled.contentLength)
        assertEquals(null, assembled.contentType)
    }

    @Test
    fun aNegativeContentLengthIsReportedAsUnknown() {
        val assembled = ResponseAssembly.assemble(
            headers = listOf("Content-Length" to "-5"),
            statusCode = 200,
            negotiatedProtocol = "h2",
            method = "GET"
        )

        assertEquals(-1L, assembled.contentLength)
    }
}
