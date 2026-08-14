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

import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger

class BodyPipeTest {

    private fun bodyPipe(
        readTimeoutMs: Long = 30_000L,
        aborts: AtomicInteger = AtomicInteger()
    ) = BodyPipe(readTimeoutMs) { aborts.incrementAndGet() }

    private fun source(text: String) = Buffer().writeUtf8(text)

    @Test
    fun failThenEofThrowsRecordedError() {
        val pipe = bodyPipe()
        val payload = source("hello")
        pipe.write(payload, payload.size)
        val recorded = IOException("cronet failed mid body")
        pipe.fail(recorded)
        pipe.closeSink()

        val sink = Buffer()
        assertEquals(5L, pipe.source.read(sink, 8192L))
        assertEquals("hello", sink.readUtf8())
        try {
            pipe.source.read(sink, 8192L)
            fail("expected the recorded failure at end of stream")
        } catch (e: IOException) {
            assertEquals(recorded, e)
        }
    }

    @Test
    fun cleanCloseYieldsEof() {
        val pipe = bodyPipe()
        val payload = source("hello")
        pipe.write(payload, payload.size)
        pipe.closeSink()

        val sink = Buffer()
        assertEquals(5L, pipe.source.read(sink, 8192L))
        assertEquals("hello", sink.readUtf8())
        assertEquals(-1L, pipe.source.read(sink, 8192L))
    }

    @Test
    fun consumerCloseFiresAbortOnce() {
        val aborts = AtomicInteger()
        val pipe = bodyPipe(aborts = aborts)
        assertEquals(0, aborts.get())

        pipe.source.close()
        pipe.source.close()

        assertEquals(1, aborts.get())
    }

    @Test
    fun stalledReadTimesOutAndAborts() {
        val aborts = AtomicInteger()
        val pipe = bodyPipe(readTimeoutMs = 250L, aborts = aborts)

        val started = System.nanoTime()
        try {
            pipe.source.read(Buffer(), 8192L)
            fail("expected the read deadline to elapse")
        } catch (_: IOException) {
            // expected
        }
        val elapsedMs = (System.nanoTime() - started) / 1_000_000

        assertTrue("read returned after ${elapsedMs}ms", elapsedMs < 10_000)
        assertEquals(1, aborts.get())
    }

    @Test
    fun stalledWriteTimesOut() {
        val pipe = bodyPipe(readTimeoutMs = 250L)
        val payload = Buffer().write(ByteArray(300 * 1024))

        val started = System.nanoTime()
        try {
            pipe.write(payload, payload.size)
            fail("expected the write deadline to elapse against an undrained pipe")
        } catch (_: IOException) {
            // expected
        }
        val elapsedMs = (System.nanoTime() - started) / 1_000_000

        assertTrue("write returned after ${elapsedMs}ms", elapsedMs < 10_000)
    }

    @Test
    fun writeAfterConsumerCloseThrows() {
        val pipe = bodyPipe()
        pipe.source.close()

        val payload = source("hello")
        try {
            pipe.write(payload, payload.size)
            fail("expected the write to fail after the consumer closed the pipe")
        } catch (_: IOException) {
            // expected
        }
    }

    @Test
    fun readAfterConsumerCloseThrows() {
        val pipe = bodyPipe()
        val payload = source("hello")
        pipe.write(payload, payload.size)
        pipe.source.close()

        var thrown: Throwable? = null
        val started = System.nanoTime()
        try {
            pipe.source.read(Buffer(), 8192L)
        } catch (e: Throwable) {
            thrown = e
        }
        val elapsedMs = (System.nanoTime() - started) / 1_000_000

        assertNotNull("a read after close must throw", thrown)
        // Fast, so a close that left the underlying source open and merely waited out the
        // read deadline would not pass.
        assertTrue("read returned after ${elapsedMs}ms", elapsedMs < 5_000)
    }

    @Test
    fun closeSinkIsIdempotentAndDoesNotAbort() {
        val aborts = AtomicInteger()
        val pipe = bodyPipe(aborts = aborts)
        pipe.closeSink()
        pipe.closeSink()

        assertEquals(0, aborts.get())
        assertEquals(-1L, pipe.source.read(Buffer(), 8192L))
    }
}
