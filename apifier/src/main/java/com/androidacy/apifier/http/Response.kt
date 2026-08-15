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

import com.androidacy.apifier.http.ResponseBody.Companion.toResponseBody
import java.io.Closeable
import java.time.Duration as JavaDuration
import java.time.Instant
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toKotlinDuration

/**
 * An HTTP response.
 *
 * [body] is always present; a response with no payload carries an empty one. Close the
 * response, or fully read its body, so the connection is released.
 */
class Response private constructor(
    val request: Request,
    val protocol: Protocol,
    val code: Int,
    val message: String,
    val headers: Headers,
    val body: ResponseBody
) : Closeable {

    val isSuccessful: Boolean get() = code in 200..299

    fun header(name: String, defaultValue: String? = null): String? = headers[name] ?: defaultValue

    fun headers(name: String): List<String> = headers.values(name)

    fun newBuilder(): Builder = Builder(this)

    override fun close() {
        body.close()
    }

    override fun toString(): String = "Response{code=$code, message=$message, url=${request.url}}"

    class Builder {

        private var request: Request? = null
        private var protocol: Protocol = Protocol.HTTP_1_1
        private var code: Int = -1
        private var message: String = ""
        private var headers: Headers.Builder = Headers.Builder()
        private var body: ResponseBody? = null

        constructor()

        internal constructor(response: Response) {
            request = response.request
            protocol = response.protocol
            code = response.code
            message = response.message
            headers = response.headers.newBuilder()
            body = response.body
        }

        fun request(request: Request): Builder = apply { this.request = request }

        fun protocol(protocol: Protocol): Builder = apply { this.protocol = protocol }

        fun code(code: Int): Builder = apply { this.code = code }

        fun message(message: String): Builder = apply { this.message = message }

        fun headers(headers: Headers): Builder = apply { this.headers = headers.newBuilder() }

        fun header(name: String, value: String): Builder = apply { headers.set(name, value) }

        fun addHeader(name: String, value: String): Builder = apply { headers.add(name, value) }

        fun removeHeader(name: String): Builder = apply { headers.removeAll(name) }

        fun body(body: ResponseBody): Builder = apply { this.body = body }

        fun build(): Response {
            val request = checkNotNull(request) { "request is not set" }
            check(code >= 0) { "code is not set" }
            return Response(
                request = request,
                protocol = protocol,
                code = code,
                message = message,
                headers = headers.build(),
                body = body ?: ByteArray(0).toResponseBody(null)
            )
        }
    }
}

/**
 * Returns this response when [Response.isSuccessful], otherwise closes its body and throws
 * [ApifierException.HttpError]. A hand-written status check that throws without closing leaks
 * the connection on every non-2xx.
 */
fun Response.successOrThrow(): Response {
    if (isSuccessful) return this
    close()
    throw ApifierException.HttpError(code)
}

/**
 * The `Retry-After` header, parsed as either delta-seconds or an HTTP-date (RFC 9110 section
 * 10.2.3), or null when the header is absent or matches neither form. A date already in the past
 * yields [Duration.ZERO] rather than a negative duration.
 */
val Response.retryAfter: Duration?
    get() {
        val value = header("Retry-After") ?: return null
        value.toLongOrNull()?.let { return it.seconds.coerceAtLeast(Duration.ZERO) }
        val date = runCatching { ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME) }
            .getOrNull() ?: return null
        return JavaDuration.between(Instant.now(), date.toInstant()).toKotlinDuration().coerceAtLeast(Duration.ZERO)
    }
