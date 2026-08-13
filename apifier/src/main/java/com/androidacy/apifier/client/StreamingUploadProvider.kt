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

import com.androidacy.apifier.http.RequestBody
import java.io.IOException
import java.nio.ByteBuffer
import okio.Buffer
import okio.Source
import org.chromium.net.UploadDataProvider
import org.chromium.net.UploadDataSink

/**
 * Feeds a [RequestBody] to Cronet through its pull contract: each [read] fills at most the
 * buffer Cronet hands in, taken straight from [RequestBody.pullSource], so an upload never holds
 * more than one read's worth of body bytes at a time.
 *
 * A body with unknown length ([RequestBody.contentLength] of -1) uploads chunked and cannot
 * rewind, since there is no byte offset to resume replaying from; [rewind] reports that as a
 * rewind error rather than reusing a source that has already given bytes away.
 */
internal class StreamingUploadProvider(
    private val body: RequestBody,
    private val onProgress: ((sent: Long, total: Long) -> Unit)?
) : UploadDataProvider() {

    private val total = body.contentLength()
    private val transfer = Buffer()
    private var source: Source = body.pullSource()
    private var sent = 0L

    override fun getLength(): Long = total

    override fun read(uploadDataSink: UploadDataSink, byteBuffer: ByteBuffer) {
        val requested = byteBuffer.remaining().toLong()
        val read = source.read(transfer, requested)
        val exhausted = read == -1L
        if (!exhausted) {
            transfer.read(byteBuffer)
            sent += read
        }
        onProgress?.invoke(sent, total)
        uploadDataSink.onReadSucceeded(total < 0 && exhausted)
    }

    override fun rewind(uploadDataSink: UploadDataSink) {
        if (total < 0) {
            uploadDataSink.onRewindError(IOException("cannot rewind a chunked body of unknown length"))
            return
        }
        source.close()
        source = body.pullSource()
        transfer.clear()
        sent = 0L
        onProgress?.invoke(0L, total)
        uploadDataSink.onRewindSucceeded()
    }

    override fun close() {
        source.close()
    }
}
