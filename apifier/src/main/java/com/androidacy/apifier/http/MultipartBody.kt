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
