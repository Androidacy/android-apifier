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
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class MediaTypeTest {

    @Test
    fun mediaTypeParsesCharset() {
        val mediaType = "application/json; charset=utf-8".toMediaTypeOrNull()

        assertEquals("application", mediaType?.type)
        assertEquals("json", mediaType?.subtype)
        assertEquals(StandardCharsets.UTF_8, mediaType?.charset)
        assertEquals("application/json; charset=utf-8", mediaType.toString())
    }

    @Test
    fun charsetParameterMayBeQuotedAndIsCaseInsensitive() {
        val mediaType = "text/plain; CHARSET=\"ISO-8859-1\"".toMediaTypeOrNull()

        assertEquals(StandardCharsets.ISO_8859_1, mediaType?.charset)
    }

    @Test
    fun typeAndSubtypeAreLowercasedButLiteralIsNot() {
        val mediaType = "Application/JSON".toMediaTypeOrNull()

        assertEquals("application", mediaType?.type)
        assertEquals("json", mediaType?.subtype)
        assertEquals("Application/JSON", mediaType.toString())
    }

    @Test
    fun malformedInputReturnsNull() {
        assertNull("".toMediaTypeOrNull())
        assertNull("text".toMediaTypeOrNull())
        assertNull("text/".toMediaTypeOrNull())
        assertNull("/plain".toMediaTypeOrNull())
        assertNull("text plain".toMediaTypeOrNull())
    }

    @Test
    fun unsupportedCharsetLeavesCharsetNull() {
        val mediaType = "text/plain; charset=definitely-not-a-charset".toMediaTypeOrNull()

        assertEquals("text", mediaType?.type)
        assertNull(mediaType?.charset)
    }
}
