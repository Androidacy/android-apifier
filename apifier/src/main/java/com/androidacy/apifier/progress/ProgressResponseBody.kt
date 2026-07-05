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
package com.androidacy.apifier.progress

import okhttp3.MediaType
import okhttp3.ResponseBody
import okio.Buffer
import okio.BufferedSource
import okio.ForwardingSource
import okio.Source
import okio.buffer
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** [ResponseBody] wrapper that reports download progress to a [ProgressListener]. */
class ProgressResponseBody(
    private val responseBody: ResponseBody,
    private val progressListener: ProgressListener
) : ResponseBody() {

    private var bufferedSource: BufferedSource? = null
    private val totalBytesRead = AtomicLong(0L)
    private val lastReportedBytes = AtomicLong(-1L)
    private val doneReported = AtomicBoolean(false)

    override fun contentType(): MediaType? = responseBody.contentType()

    override fun contentLength(): Long = responseBody.contentLength()

    override fun source(): BufferedSource {
        if (bufferedSource == null) {
            bufferedSource = source(responseBody.source()).buffer()
        }
        return bufferedSource!!
    }

    private fun source(source: Source): Source {
        return object : ForwardingSource(source) {
            @Throws(IOException::class)
            override fun read(sink: Buffer, byteCount: Long): Long {
                val bytesRead = super.read(sink, byteCount)
                val current = if (bytesRead != -1L) {
                    totalBytesRead.addAndGet(bytesRead)
                } else {
                    totalBytesRead.get()
                }

                if (bytesRead == -1L) {
                    // EOF may land on a byte total already reported by the previous
                    // read, so the dedup guard below would swallow the done signal.
                    if (!doneReported.getAndSet(true)) {
                        progressListener.update(current, responseBody.contentLength(), true)
                    }
                } else {
                    val last = lastReportedBytes.get()
                    if (current != last && lastReportedBytes.compareAndSet(last, current)) {
                        progressListener.update(current, responseBody.contentLength(), false)
                    }
                }
                return bytesRead
            }
        }
    }
}
