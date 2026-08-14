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
import okio.Buffer
import okio.BufferedSink
import okio.Source
import okio.source

/**
 * The payload of a request.
 *
 * [writeTo] must be replayable: a retry or a redirect writes the same body again, so an
 * implementation reads its source from the start on every call and never consumes it once.
 */
abstract class RequestBody {

    abstract fun contentType(): MediaType?

    /** The exact byte count [writeTo] will produce, or -1 when it is not known ahead of time. */
    open fun contentLength(): Long = -1L

    abstract fun writeTo(sink: BufferedSink)

    /**
     * A fresh, pull-based view of this body's bytes, read incrementally by the upload provider
     * instead of all at once. Called again on every rewind, so an override that owns a resource
     * (a file handle, a part's own source) must reopen it here; a spent one cannot be reused.
     *
     * The default buffers the whole [writeTo] output once, the same memory shape a body without
     * a pull-friendly source had before this seam existed; bodies whose bytes are already
     * resident or file-backed override this to avoid that copy.
     */
    internal open fun pullSource(): Source = Buffer().also { writeTo(it) }

    /**
     * True when [pullSource] reads from a source already resident outside the JVM heap (a
     * file). Upload progress is only reported for this shape: an in-memory body is a few
     * kilobytes at most, small enough that reporting it would snap a caller's count straight to
     * full and then reset it for the download that follows.
     */
    internal open val streamsFromDisk: Boolean = false

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

                override fun pullSource(): Source = ByteArraySource(bytes)
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

                override fun pullSource(): Source = file.source()

                override val streamsFromDisk: Boolean = true
            }
        }
    }
}

/** Streams an already-resident array without copying it into a [Buffer] up front. */
private class ByteArraySource(private val bytes: ByteArray) : Source {
    private var offset = 0

    override fun read(sink: Buffer, byteCount: Long): Long {
        if (offset >= bytes.size) return -1L
        val toRead = minOf(byteCount, (bytes.size - offset).toLong()).toInt()
        sink.write(bytes, offset, toRead)
        offset += toRead
        return toRead.toLong()
    }

    override fun timeout(): okio.Timeout = okio.Timeout.NONE

    override fun close() = Unit
}
