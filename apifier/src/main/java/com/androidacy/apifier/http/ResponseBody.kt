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

import androidx.annotation.Discouraged
import java.io.Closeable
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okio.Buffer
import okio.BufferedSource
import okio.buffer
import okio.sink

/**
 * A response payload, read as a stream.
 *
 * The bytes arrive from the network as they are read, so a body is consumed once: reading it
 * drains the source and closes it, and any later read sees an exhausted stream. Close a body
 * you do not read, either directly or through [Response.close], or the underlying connection
 * stays held open.
 *
 * Every instance originates in this library, through [asResponseBody] or [toResponseBody]. The
 * abstract [source] is internal, so a subclass cannot be built outside this module.
 */
abstract class ResponseBody : Closeable {

    abstract fun contentType(): MediaType?

    /** The length announced by the response, or -1 when the length was not known. */
    abstract fun contentLength(): Long

    @PublishedApi
    internal abstract fun source(): BufferedSource

    override fun close() {
        source().close()
    }

    companion object {
        @JvmStatic
        @JvmName("create")
        fun ByteArray.toResponseBody(contentType: MediaType? = null): ResponseBody {
            val buffer = Buffer().write(this)
            return buffer.asResponseBody(contentType, size.toLong())
        }

        @JvmStatic
        @JvmName("create")
        fun BufferedSource.asResponseBody(contentType: MediaType?, contentLength: Long = -1L): ResponseBody {
            val source = this
            return object : ResponseBody() {
                override fun contentType(): MediaType? = contentType

                override fun contentLength(): Long = contentLength

                override fun source(): BufferedSource = source
            }
        }
    }
}

/**
 * Reads the body to its end on [Dispatchers.IO] and closes it. Holds the whole body in memory
 * at once; a large or unknown-length response belongs on [writeTo] or [read].
 */
@Discouraged("Holds the whole body in memory. Use ResponseBody.writeTo or ResponseBody.read for a streaming response.")
@Deprecated(
    "Holds the whole body in memory. Use ResponseBody.writeTo or ResponseBody.read for a " +
        "streaming response.",
    level = DeprecationLevel.WARNING
)
suspend fun ResponseBody.bytes(): ByteArray = withContext(Dispatchers.IO) {
    use { it.source().readByteArray() }
}

/**
 * Reads the body to its end as text on [Dispatchers.IO] and closes it, decoding with the
 * charset of [ResponseBody.contentType] and UTF-8 when it names none. Holds the whole body in
 * memory at once; a large or unknown-length response belongs on [writeTo] or [read].
 */
suspend fun ResponseBody.string(): String {
    val charset = contentType()?.charset ?: Charsets.UTF_8
    return withContext(Dispatchers.IO) {
        use { it.source().readString(charset) }
    }
}

/**
 * Streams the body to [file] on [Dispatchers.IO] and closes the body, without holding it in
 * memory. Overwrites an existing file. On failure the partial file is left in place and the
 * [java.io.IOException] propagates; deleting it is the caller's call to make.
 *
 * @return the number of bytes written.
 */
suspend fun ResponseBody.writeTo(file: File): Long = withContext(Dispatchers.IO) {
    use { body ->
        file.sink().buffer().use { sink -> sink.writeAll(body.source()) }
    }
}

/**
 * Hands the body's [BufferedSource] to [block] on [Dispatchers.IO] and closes the body once
 * [block] returns or throws. The source is valid only for the duration of [block]; a reference
 * kept past it sees a closed source.
 */
suspend fun <T> ResponseBody.read(block: (BufferedSource) -> T): T = withContext(Dispatchers.IO) {
    use { block(it.source()) }
}
