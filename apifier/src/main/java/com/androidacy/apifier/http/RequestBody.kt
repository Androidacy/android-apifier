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

import java.io.File
import okio.BufferedSink
import okio.source

/**
 * The payload of a request.
 *
 * [writeTo] must be replayable: a retry or a redirect writes the same body again, so an
 * implementation reads its source from the start on every call rather than consuming it once.
 */
abstract class RequestBody {

    abstract fun contentType(): MediaType?

    /** The exact byte count [writeTo] will produce, or -1 when it is not known ahead of time. */
    open fun contentLength(): Long = -1L

    abstract fun writeTo(sink: BufferedSink)

    companion object {
        /** Encodes with the charset of [contentType], or UTF-8 when it names none. */
        @JvmStatic
        @JvmName("create")
        fun String.toRequestBody(contentType: MediaType? = null): RequestBody {
            val charset = contentType?.charset ?: Charsets.UTF_8
            return toByteArray(charset).toRequestBody(contentType)
        }

        @JvmStatic
        @JvmName("create")
        fun ByteArray.toRequestBody(contentType: MediaType? = null): RequestBody {
            val bytes = this
            return object : RequestBody() {
                override fun contentType(): MediaType? = contentType

                override fun contentLength(): Long = bytes.size.toLong()

                override fun writeTo(sink: BufferedSink) {
                    sink.write(bytes)
                }
            }
        }

        @JvmStatic
        @JvmName("create")
        fun File.asRequestBody(contentType: MediaType? = null): RequestBody {
            val file = this
            return object : RequestBody() {
                override fun contentType(): MediaType? = contentType

                override fun contentLength(): Long = file.length()

                override fun writeTo(sink: BufferedSink) {
                    file.source().use { sink.writeAll(it) }
                }
            }
        }
    }
}
