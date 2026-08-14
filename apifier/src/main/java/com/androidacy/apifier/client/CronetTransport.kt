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
import com.androidacy.apifier.http.Call
import com.androidacy.apifier.http.Headers
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.progress.ProgressListener
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
class CronetTransport(
    private val engine: CronetEngine,
    private val readTimeoutMs: Long,
    private val executor: ExecutorService = Executors.newCachedThreadPool { runnable ->
        Thread(runnable, "Cronet-IO").apply { isDaemon = true }
    }
) : Call.Factory {

    /** Label for the engine serving these calls, reported with observation events. */
    val provider: String = engine.versionString

    override fun newCall(request: Request): Call = newCall(request, null)

    internal fun newCall(request: Request, listener: TransportListener?): Call =
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
            val progressListener = request.tag(ProgressListener::class.java)
            setUploadDataProvider(
                StreamingUploadProvider(body) { sent, total ->
                    bytesSent.set(sent)
                    progressListener?.update(sent, total, total in 0..sent)
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
     * [effectiveUri] is the URL that answered, so after a redirect it is the target rather than
     * the URL the request was addressed to. The response's `Set-Cookie` headers are scoped to it.
     */
    fun onResponseStarted(ttfbMillis: Long, effectiveUri: Uri)

    fun onTransferComplete(bytesSent: Long, bytesReceived: Long)
}
