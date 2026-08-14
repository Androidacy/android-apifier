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
import okio.ForwardingSource
import okio.Pipe
import okio.Source
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Carries response bytes from the transport callback thread to the consumer's reading thread.
 *
 * [onAbort] runs once when the consumer stops reading or a deadline elapses. Cronet only
 * advances a request through read() or cancel(), so a request whose body is abandoned stays
 * paused for the engine's lifetime unless something cancels it.
 */
internal class BodyPipe(readTimeoutMs: Long, private val onAbort: () -> Unit) {

    private companion object {
        const val PIPE_BUFFER_SIZE = 256L * 1024
    }

    private val pipe = Pipe(PIPE_BUFFER_SIZE)
    private val failure = AtomicReference<IOException?>()
    private val aborted = AtomicBoolean(false)

    init {
        // The pipe is not reached by the HTTP client's own read/write timeouts, so a stalled
        // reader (headers then silence) or a stalled sink (a body nobody drains) would block
        // forever without deadlines on both ends.
        pipe.source.timeout().timeout(readTimeoutMs, TimeUnit.MILLISECONDS)
        pipe.sink.timeout().timeout(readTimeoutMs, TimeUnit.MILLISECONDS)
    }

    val source: Source = object : ForwardingSource(pipe.source) {
        override fun read(sink: Buffer, byteCount: Long): Long {
            val bytesRead = try {
                super.read(sink, byteCount)
            } catch (e: IOException) {
                abort()
                throw e
            }
            if (bytesRead == -1L) {
                // Okio's Pipe has no error channel: a mid-body transport failure closes the
                // sink, which reaches the reader as a clean EOF. Raise the recorded error so
                // the caller sees the failure instead of a silently truncated body.
                failure.get()?.let { throw it }
            }
            return bytesRead
        }

        override fun close() {
            abort()
            super.close()
        }
    }

    fun write(source: Buffer, byteCount: Long) {
        pipe.sink.write(source, byteCount)
        pipe.sink.flush()
    }

    fun closeSink() {
        try {
            pipe.sink.close()
        } catch (_: IOException) {
        }
    }

    fun fail(e: IOException) {
        failure.compareAndSet(null, e)
    }

    private fun abort() {
        if (aborted.compareAndSet(false, true)) onAbort()
    }
}
