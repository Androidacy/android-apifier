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

import java.io.Closeable
import java.io.InputStream
import okio.Buffer
import okio.BufferedSource

/**
 * A response payload, read as a stream.
 *
 * The bytes arrive from the network as they are read, so a body is consumed once: [bytes] and
 * [string] drain the source and close it, and any later read sees an exhausted stream. Close
 * a body you do not read, either directly or through [Response.close], or the underlying
 * connection stays held open.
 */
abstract class ResponseBody : Closeable {

    abstract fun contentType(): MediaType?

    /** The length announced by the response, or -1 when the length was not known. */
    abstract fun contentLength(): Long

    abstract fun source(): BufferedSource

    fun byteStream(): InputStream = source().inputStream()

    /** Reads the body to its end and closes it. */
    fun bytes(): ByteArray = use { it.source().readByteArray() }

    /**
     * Reads the body to its end as text and closes it, decoding with the charset of
     * [contentType] and UTF-8 when it names none.
     */
    fun string(): String {
        val charset = contentType()?.charset ?: Charsets.UTF_8
        return use { it.source().readString(charset) }
    }

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
        fun BufferedSource.asResponseBody(contentType: MediaType?, contentLength: Long): ResponseBody {
            val source = this
            return object : ResponseBody() {
                override fun contentType(): MediaType? = contentType

                override fun contentLength(): Long = contentLength

                override fun source(): BufferedSource = source
            }
        }
    }
}
