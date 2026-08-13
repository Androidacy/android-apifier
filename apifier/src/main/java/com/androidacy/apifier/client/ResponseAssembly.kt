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

import com.androidacy.apifier.http.Protocol

/**
 * Turns the metadata Cronet reports for a response into the shape a client response needs.
 *
 * Pure and transport-free so it can be tested without an engine.
 */
object ResponseAssembly {

    private val ENCODINGS_HANDLED_BY_CRONET = setOf("br", "deflate", "gzip", "x-gzip", "zstd")

    data class Assembled(
        val headers: List<Pair<String, String>>,
        val contentType: String?,
        val contentLength: Long,
        val protocol: Protocol,
        val bodyDecodedByCronet: Boolean
    )

    fun assemble(
        headers: List<Pair<String, String>>,
        statusCode: Int,
        negotiatedProtocol: String,
        method: String
    ): Assembled {
        val contentEncodings = valuesOf(headers, "Content-Encoding")
            .flatMap { it.split(",").map(String::trim).filter(String::isNotEmpty) }
        // Cronet natively decodes certain encodings. When it does, the original
        // Content-Encoding and Content-Length headers no longer describe the body
        // the caller will read.
        val decoded = contentEncodings.isNotEmpty() &&
            ENCODINGS_HANDLED_BY_CRONET.containsAll(contentEncodings)

        val contentLength = if (decoded || method == "HEAD") {
            -1L
        } else {
            valuesOf(headers, "Content-Length").lastOrNull()?.toLongOrNull() ?: -1L
        }

        val outHeaders = if (decoded) {
            headers.filterNot {
                it.first.equals("Content-Encoding", ignoreCase = true) ||
                    it.first.equals("Content-Length", ignoreCase = true)
            }
        } else {
            headers
        }

        return Assembled(
            headers = outHeaders,
            contentType = valuesOf(headers, "Content-Type").lastOrNull(),
            contentLength = contentLength,
            protocol = protocolOf(negotiatedProtocol),
            bodyDecodedByCronet = decoded
        )
    }

    private fun valuesOf(headers: List<Pair<String, String>>, name: String): List<String> =
        headers.filter { it.first.equals(name, ignoreCase = true) }.map { it.second }

    private fun protocolOf(negotiatedProtocol: String): Protocol = when {
        negotiatedProtocol.contains("h3") || negotiatedProtocol.contains("quic") -> Protocol.QUIC
        negotiatedProtocol.contains("h2") || negotiatedProtocol.contains("spdy") -> Protocol.HTTP_2
        negotiatedProtocol.contains("http/1.1") -> Protocol.HTTP_1_1
        else -> Protocol.HTTP_1_0
    }
}
