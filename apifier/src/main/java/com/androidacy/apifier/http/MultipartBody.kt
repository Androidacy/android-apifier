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
import com.androidacy.apifier.http.RequestBody.Companion.toRequestBody
import java.util.UUID
import okio.Buffer
import okio.BufferedSink
import okio.Source
import okio.Timeout

/**
 * A `multipart/form-data` request body.
 *
 * [writeTo] can run more than once, so a retry or a redirect resends the same bytes, provided
 * every part body is itself replayable.
 */
class MultipartBody private constructor(
    private val type: MediaType,
    val boundary: String,
    private val parts: List<Part>
) : RequestBody() {

    private class Part(val name: String, val filename: String?, val body: RequestBody)

    private val typeWithBoundary: MediaType =
        checkNotNull("$type; boundary=$boundary".toMediaTypeOrNull()) { "invalid multipart type $type" }

    override fun contentType(): MediaType = typeWithBoundary

    /** The exact framed length, or -1 as soon as one part does not know its own length. */
    override fun contentLength(): Long = writeOrCount(null)

    override fun writeTo(sink: BufferedSink) {
        writeOrCount(sink)
    }

    /**
     * Frame headers and trailers are tiny generated buffers; only part bodies can be large, so
     * they stream from their own [pullSource][RequestBody.pullSource] instead of being written
     * into a shared sink up front.
     *
     * Each part's [pullSource][RequestBody.pullSource] runs lazily, only once [SequencedSource]
     * reaches it and has already closed the part before it: a 20-part body never holds more than
     * one part's handle open, and a part that fails to open never strands the ones opened ahead
     * of it, because none of them are opened ahead of it.
     */
    override fun pullSource(): Source {
        val factories = mutableListOf<() -> Source>()
        for (part in parts) {
            factories += {
                Buffer().apply {
                    writeUtf8("--").writeUtf8(boundary).writeUtf8(CRLF)
                    writeUtf8("Content-Disposition: form-data; name=")
                    writeQuoted(this, part.name)
                    if (part.filename != null) {
                        writeUtf8("; filename=")
                        writeQuoted(this, part.filename)
                    }
                    writeUtf8(CRLF)
                    part.body.contentType()
                        ?.let { writeUtf8("Content-Type: ").writeUtf8(it.toString()).writeUtf8(CRLF) }
                    writeUtf8(CRLF)
                }
            }
            factories += { part.body.pullSource() }
            factories += { Buffer().writeUtf8(CRLF) }
        }
        factories += { Buffer().writeUtf8("--").writeUtf8(boundary).writeUtf8("--").writeUtf8(CRLF) }
        return SequencedSource(factories)
    }

    private fun writeOrCount(sink: BufferedSink?): Long {
        val counter = if (sink == null) Buffer() else null
        val out = sink ?: counter!!
        var byteCount = 0L

        fun harvest() {
            if (counter != null) {
                byteCount += counter.size
                counter.clear()
            }
        }

        for (part in parts) {
            out.writeUtf8("--").writeUtf8(boundary).writeUtf8(CRLF)
            out.writeUtf8("Content-Disposition: form-data; name=")
            writeQuoted(out, part.name)
            if (part.filename != null) {
                out.writeUtf8("; filename=")
                writeQuoted(out, part.filename)
            }
            out.writeUtf8(CRLF)
            part.body.contentType()?.let { out.writeUtf8("Content-Type: ").writeUtf8(it.toString()).writeUtf8(CRLF) }
            out.writeUtf8(CRLF)
            harvest()

            if (sink != null) {
                part.body.writeTo(sink)
            } else {
                val partLength = part.body.contentLength()
                if (partLength == -1L) return -1L
                byteCount += partLength
            }

            out.writeUtf8(CRLF)
            harvest()
        }

        out.writeUtf8("--").writeUtf8(boundary).writeUtf8("--").writeUtf8(CRLF)
        harvest()
        return byteCount
    }

    private fun writeQuoted(sink: BufferedSink, value: String) {
        sink.writeUtf8("\"")
        for (character in value) {
            when (character) {
                '\n' -> sink.writeUtf8("%0A")
                '\r' -> sink.writeUtf8("%0D")
                '"' -> sink.writeUtf8("%22")
                else -> sink.writeUtf8(character.toString())
            }
        }
        sink.writeUtf8("\"")
    }

    class Builder(private val boundary: String = UUID.randomUUID().toString()) {

        private var type: MediaType = FORM
        private val parts = mutableListOf<Part>()

        fun setType(type: MediaType): Builder = apply {
            require(type.type == "multipart") { "type must be multipart: $type" }
            this.type = type
        }

        fun addFormDataPart(name: String, value: String): Builder =
            addFormDataPart(name, null, value.toRequestBody(null))

        fun addFormDataPart(name: String, filename: String?, body: RequestBody): Builder = apply {
            parts.add(Part(name, filename, body))
        }

        fun build(): MultipartBody {
            require(parts.isNotEmpty()) { "multipart body has no parts" }
            return MultipartBody(type, boundary, parts.toList())
        }
    }

    companion object {
        private const val CRLF = "\r\n"

        @JvmField
        val FORM: MediaType = checkNotNull("multipart/form-data".toMediaTypeOrNull())
    }
}

/**
 * Opens each of [factories] only when reading reaches it, and closes it before opening the next,
 * so at most one is ever open. A factory that throws leaves nothing new to close; whatever came
 * before it is already closed by the time it runs.
 */
private class SequencedSource(private val factories: List<() -> Source>) : Source {
    private var index = 0
    private var current: Source? = null

    override fun read(sink: Buffer, byteCount: Long): Long {
        while (index < factories.size) {
            val source = current ?: factories[index]().also { current = it }
            val read = source.read(sink, byteCount)
            if (read != -1L) return read
            source.close()
            current = null
            index++
        }
        return -1L
    }

    override fun timeout(): Timeout = Timeout.NONE

    override fun close() {
        current?.close()
        current = null
        index = factories.size
    }
}
