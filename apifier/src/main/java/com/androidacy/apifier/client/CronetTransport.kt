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

import android.net.Uri
import com.androidacy.apifier.http.Headers
import com.androidacy.apifier.http.Request
import org.chromium.net.CronetEngine
import org.chromium.net.UrlRequest
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

/**
 * Runs calls directly on a [CronetEngine].
 *
 * Each call is a single attempt. Retries, cookies and observation are layered above the
 * transport and reach it through [TransportListener].
 */
internal class CronetTransport(
    private val engine: CronetEngine,
    private val readTimeoutMs: Long,
    private val executor: ExecutorService = Executors.newCachedThreadPool { runnable ->
        Thread(runnable, "Cronet-IO").apply { isDaemon = true }
    }
) {

    /** Label for the engine serving these calls, reported with observation events. */
    val provider: String = engine.versionString

    internal fun newCall(request: Request, listener: TransportListener?): CronetCall =
        CronetCall(request, readTimeoutMs, listener, executor) { callback, bytesSent ->
            buildUrlRequest(request, callback, bytesSent)
        }

    /** Stops the callback executor. The engine outlives it and is closed by its owner. */
    fun shutdown() {
        executor.shutdown()
    }

    private fun buildUrlRequest(
        request: Request,
        callback: UrlRequest.Callback,
        bytesSent: AtomicLong
    ): UrlRequest = engine.newUrlRequestBuilder(request.url, callback, executor).apply {
        setHttpMethod(request.method)

        val hasContentType = request.headers.names().any { it.equals("Content-Type", ignoreCase = true) }
        for (index in 0 until request.headers.size) {
            addHeader(request.headers.name(index), request.headers.value(index))
        }

        request.body?.let { body ->
            if (!hasContentType) {
                body.contentType()?.let { addHeader("Content-Type", it.toString()) }
            }
            setUploadDataProvider(
                StreamingUploadProvider(body, request.tag(ProgressSink::class.java)?.flow) {
                    bytesSent.set(it)
                },
                executor
            )
        }
    }.build()
}

/** Transport events the request pipeline observes. */
internal interface TransportListener {

    /**
     * A redirect was accepted. [hopUri] is the URL that produced the redirect response, which is
     * the URL its `Set-Cookie` headers belong to, not the location being followed.
     */
    fun onRedirect(hopUri: Uri, hopHeaders: Headers)

    /**
     * [effectiveUri] is the URL that answered. After a redirect that is the target, not the URL
     * the request was addressed to, and the response's `Set-Cookie` headers are scoped to it.
     */
    fun onResponseStarted(ttfbMillis: Long, effectiveUri: Uri)

    fun onTransferComplete(bytesSent: Long, bytesReceived: Long)
}
