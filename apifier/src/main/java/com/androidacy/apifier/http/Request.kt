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

import android.net.Uri

/**
 * An HTTP request.
 *
 * [uri] is parsed once by [Builder.build] and carries the host used for cookie matching and
 * for the transport's trust check, so neither has to re-parse [url].
 */
class Request private constructor(
    val url: String,
    val uri: Uri,
    val method: String,
    val headers: Headers,
    val body: RequestBody?,
    private val tags: Map<Class<*>, Any>
) {

    /** The last value for [name] among this request's headers, or null. */
    fun header(name: String): String? = headers[name]

    fun headers(name: String): List<String> = headers.values(name)

    /** The tag attached under [type] by [Builder.tag], or null when none was attached. */
    fun <T> tag(type: Class<T>): T? = type.cast(tags[type])

    fun newBuilder(): Builder = Builder(this)

    override fun toString(): String = "Request{method=$method, url=$url}"

    class Builder {

        private var url: String? = null
        private var method: String = "GET"
        private var headers: Headers.Builder = Headers.Builder()
        private var body: RequestBody? = null
        private var tags: MutableMap<Class<*>, Any> = mutableMapOf()

        constructor()

        internal constructor(request: Request) {
            url = request.url
            method = request.method
            headers = request.headers.newBuilder()
            body = request.body
            tags = request.tags.toMutableMap()
        }

        /** The URL to call. It must be `https` with a host; [build] rejects anything else. */
        fun url(url: String): Builder = apply { this.url = url }

        fun get(): Builder = method("GET", null)

        fun head(): Builder = method("HEAD", null)

        fun post(body: RequestBody): Builder = method("POST", body)

        fun put(body: RequestBody): Builder = method("PUT", body)

        fun patch(body: RequestBody): Builder = method("PATCH", body)

        fun delete(body: RequestBody? = null): Builder = method("DELETE", body)

        fun method(method: String, body: RequestBody?): Builder = apply {
            require(method.isNotEmpty()) { "method is empty" }
            require(body == null || permitsRequestBody(method)) { "method $method must not have a body" }
            require(body != null || !requiresRequestBody(method)) { "method $method must have a body" }
            this.method = method
            this.body = body
        }

        /** Replaces every existing value for [name]. */
        fun header(name: String, value: String): Builder = apply { headers.set(name, value) }

        /** Adds a value for [name], keeping any already present. */
        fun addHeader(name: String, value: String): Builder = apply { headers.add(name, value) }

        fun removeHeader(name: String): Builder = apply { headers.removeAll(name) }

        fun headers(headers: Headers): Builder = apply { this.headers = headers.newBuilder() }

        /** Attaches a caller-owned value for correlating this request with its response. */
        fun <T> tag(type: Class<T>, tag: T?): Builder = apply {
            if (tag == null) tags.remove(type) else tags[type] = tag
        }

        fun build(): Request {
            val url = requireNotNull(url) { "url is not set" }
            val uri = Uri.parse(url)
            require(uri.scheme.equals("https", ignoreCase = true)) {
                "url must use https: $url"
            }
            require(!uri.host.isNullOrEmpty()) { "url has no host: $url" }
            return Request(url, uri, method, headers.build(), body, tags.toMap())
        }

        private fun permitsRequestBody(method: String): Boolean = method != "GET" && method != "HEAD"

        private fun requiresRequestBody(method: String): Boolean =
            method == "POST" || method == "PUT" || method == "PATCH" || method == "PROPPATCH" || method == "REPORT"
    }
}
