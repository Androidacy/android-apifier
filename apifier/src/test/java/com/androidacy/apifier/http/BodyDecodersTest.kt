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

import com.androidacy.apifier.http.ResponseBody.Companion.asResponseBody
import com.androidacy.apifier.http.ResponseBody.Companion.toResponseBody
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import okio.Buffer
import okio.ForwardingSource
import okio.Source
import okio.Timeout
import okio.buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@Serializable
private data class Widget(val name: String, val count: Int)

@RunWith(RobolectricTestRunner::class)
class BodyDecodersTest {

    @Test
    fun jsonDecodesFromTheBodySource() = runTest {
        val body = """{"name":"bolt","count":3}""".toByteArray().toResponseBody()

        val widget = body.json<Widget>()

        assertEquals(Widget("bolt", 3), widget)
    }

    @Test
    fun jsonClosesTheBody() = runTest {
        var closed = false
        val source = object : ForwardingSource(Buffer().writeUtf8("""{"name":"bolt","count":3}""")) {
            override fun close() {
                closed = true
                super.close()
            }
        }.buffer()
        val body = source.asResponseBody(null)

        body.json<Widget>()

        assertTrue(closed)
    }

    @Test
    fun jsonPropagatesAMalformedPayload() = runTest {
        val body = "not json".toByteArray().toResponseBody()

        val thrown = try {
            body.json<Widget>()
            null
        } catch (e: SerializationException) {
            e
        }

        assertNotNull(thrown)
    }

    @Test
    fun linesEmitsEachLineInOrder() = runTest {
        val body = "first\nsecond\nthird".toByteArray().toResponseBody()

        val lines = mutableListOf<String>()
        body.lines().collect { lines.add(it) }

        assertEquals(listOf("first", "second", "third"), lines)
    }

    @Test
    fun linesClosesTheBodyOnCancellation() = runTest {
        var closed = false
        val source = object : Source {
            override fun read(sink: Buffer, byteCount: Long): Long {
                sink.writeUtf8("line\n")
                return 5L
            }

            override fun timeout(): Timeout = Timeout.NONE

            override fun close() {
                closed = true
            }
        }.buffer()
        val body = source.asResponseBody(null, -1L)

        val received = mutableListOf<String>()
        val job = launch {
            body.lines().collect { line ->
                received.add(line)
                currentCoroutineContext().cancel()
            }
        }
        job.join()

        assertTrue(received.isNotEmpty())
        assertTrue(closed)
    }
}
