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
import com.androidacy.apifier.http.ApifierException
import com.androidacy.apifier.http.Headers
import com.androidacy.apifier.http.MediaType.Companion.toMediaTypeOrNull
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.http.Response
import com.androidacy.apifier.http.ResponseBody.Companion.asResponseBody
import com.androidacy.apifier.http.ResponseBody.Companion.toResponseBody
import com.androidacy.apifier.http.toApifierException
import kotlinx.coroutines.suspendCancellableCoroutine
import okio.Buffer
import okio.buffer
import org.chromium.net.CronetException
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo
import org.chromium.net.apihelpers.ImplicitFlowControlCallback
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resumeWithException

/**
 * Builds the [UrlRequest] a call will run.
 *
 * [bytesSent] is handed to the upload provider so the call can report the sent total at its
 * terminal state without reaching back into the engine.
 */
internal fun interface UrlRequestFactory {
    fun create(callback: UrlRequest.Callback, bytesSent: AtomicLong): UrlRequest
}

/**
 * Terminal outcome of a [CronetCall]. Internal-only, so unlike the public `Callback` it carries
 * no `Call` reference for a caller to read back.
 */
internal interface CallOutcome {
    fun onSuccess(response: Response)
    fun onFailure(e: IOException)
}

/**
 * One attempt at [request], run on a Cronet engine.
 *
 * The callback delivery and the body stream are separate: [CallOutcome] fires as soon as the
 * headers arrive, and the body flows through a [BodyPipe] afterwards, so a failure partway
 * through the body reaches the reader; the callback has already fired by then.
 *
 * [deliveryExecutor] must not be the thread that drives the engine callbacks. The base callback
 * arms the next read only after `onResponseStarted` returns, so a consumer that drains the body
 * inside `onResponse` would wait for bytes that cannot arrive until it yields.
 */
internal class CronetCall(
    private val request: Request,
    readTimeoutMs: Long,
    private val listener: TransportListener?,
    private val deliveryExecutor: Executor,
    private val urlRequestFactory: UrlRequestFactory
) : AttemptCall {

    private companion object {
        const val MAX_REDIRECTS = 20
        val CREDENTIAL_HEADERS = listOf("Cookie", "Authorization", "Proxy-Authorization")
    }

    private val urlRequest = AtomicReference<UrlRequest?>()
    private val enqueued = AtomicBoolean(false)
    private val canceled = AtomicBoolean(false)
    private val delivered = AtomicBoolean(false)
    private val transferReported = AtomicBoolean(false)
    private val bytesSent = AtomicLong()
    private val bytesReceived = AtomicLong()
    private val transferBuffer = Buffer()
    private val bodyPipe = BodyPipe(readTimeoutMs) { urlRequest.get()?.cancel() }

    @Volatile
    private var outcome: CallOutcome? = null

    @Volatile
    private var startNanos = 0L

    private var redirectCount = 0

    /**
     * Host the request was built for, when it carries a `Cookie`, `Authorization` or
     * `Proxy-Authorization` header, or null when it carries none of those.
     *
     * Cronet follows redirects inside one request and re-sends the caller's extra headers on
     * every hop, and Chromium's redirect header update (`net/url_request/redirect_util.cc`)
     * rewrites `Origin` and the `Content-*` set but leaves the rest, these included, alone.
     * Nothing else in this path is host-aware, so without this a credential would follow a hop
     * to any https host.
     */
    private val credentialScopeHost: String? =
        if (CREDENTIAL_HEADERS.none { request.header(it) != null }) null else request.uri.host?.lowercase()

    fun enqueue(outcome: CallOutcome) {
        check(enqueued.compareAndSet(false, true)) { "Call already enqueued" }
        this.outcome = outcome

        if (canceled.get()) {
            deliverFailure(ApifierException.Cancelled())
            // No UrlRequest was ever started, so no onCanceled is coming to report the transfer.
            // Without this the listener's completion never fires and whatever it defers is lost.
            reportTransfer()
            return
        }

        val started = urlRequestFactory.create(cronetCallback, bytesSent)
        urlRequest.set(started)
        startNanos = System.nanoTime()
        started.start()
        // A cancel that arrived before the request existed found nothing to cancel.
        if (canceled.get()) started.cancel()
    }

    override suspend fun await(): Response = suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { cancel() }
        enqueue(object : CallOutcome {
            override fun onSuccess(response: Response) {
                // A cancel that lands between the delivery and the resume leaves the caller with
                // no reference to close, and the body holds the connection open.
                continuation.resume(response) { _, undelivered, _ -> undelivered.close() }
            }

            override fun onFailure(e: IOException) {
                continuation.resumeWithException(e)
            }
        })
    }

    override fun cancel() {
        if (!canceled.compareAndSet(false, true)) return
        urlRequest.get()?.cancel()
        val cancellation = ApifierException.Cancelled()
        bodyPipe.fail(cancellation)
        deliverFailure(cancellation)
    }

    private fun deliverResponse(response: Response) {
        val target = outcome ?: return
        if (delivered.compareAndSet(false, true)) {
            deliver { target.onSuccess(response) }
        }
    }

    private fun deliverFailure(e: IOException) {
        val target = outcome ?: return
        if (delivered.compareAndSet(false, true)) {
            deliver { target.onFailure(e) }
        }
    }

    private fun deliver(delivery: () -> Unit) {
        try {
            deliveryExecutor.execute(delivery)
        } catch (_: RejectedExecutionException) {
            // The transport shut down between claiming the delivery and handing it off. The
            // claim cannot be given back, so running here is the last path to a terminal
            // callback; the alternative is a consumer that waits forever.
            delivery()
        }
    }

    /** Records [e] on the body channel and delivers it when no response was handed over yet. */
    private fun failCall(e: ApifierException) {
        bodyPipe.fail(e)
        bodyPipe.closeSink()
        deliverFailure(e)
        reportTransfer()
    }

    private fun reportTransfer() {
        if (transferReported.compareAndSet(false, true)) {
            listener?.onTransferComplete(bytesSent.get(), bytesReceived.get())
        }
    }

    private val cronetCallback = object : ImplicitFlowControlCallback() {

        override fun shouldFollowRedirect(info: UrlResponseInfo, newLocationUrl: String): Boolean {
            redirectCount++
            val refusal = when {
                redirectCount > MAX_REDIRECTS -> "Too many redirects ($MAX_REDIRECTS)"
                !newLocationUrl.startsWith("https://", ignoreCase = true) ->
                    "Redirect to non-HTTPS URL rejected: $newLocationUrl"
                credentialScopeHost != null &&
                    Uri.parse(newLocationUrl).host?.lowercase() != credentialScopeHost ->
                    "Redirect to another host rejected while carrying credentials: $newLocationUrl"
                else -> null
            }
            if (refusal != null) {
                // Returning false cancels the request, which is the only teardown the base
                // callback performs; the reason has to be recorded here or it is lost.
                failCall(ApifierException.RedirectRefused(refusal))
                return false
            }

            listener?.onRedirect(
                Uri.parse(info.url),
                Headers.of(info.allHeadersAsList.map { it.key to it.value })
            )
            return true
        }

        override fun onResponseStarted(info: UrlResponseInfo) {
            listener?.onResponseStarted(
                (System.nanoTime() - startNanos) / 1_000_000,
                Uri.parse(info.url)
            )

            val assembled = ResponseAssembly.assemble(
                headers = info.allHeadersAsList.map { it.key to it.value },
                statusCode = info.httpStatusCode,
                negotiatedProtocol = info.negotiatedProtocol,
                method = request.method
            )
            val contentType = assembled.contentType?.toMediaTypeOrNull()
            val body = if (assembled.bodyless) {
                bodyPipe.closeSink()
                ByteArray(0).toResponseBody(contentType)
            } else {
                bodyPipe.source.buffer().asResponseBody(contentType, assembled.contentLength)
            }

            deliverResponse(
                Response.Builder()
                    .request(request)
                    .protocol(assembled.protocol)
                    .code(info.httpStatusCode)
                    .message(info.httpStatusText)
                    .headers(Headers.of(assembled.headers))
                    .body(body)
                    .build()
            )
        }

        override fun onBodyChunkRead(info: UrlResponseInfo, byteBuffer: ByteBuffer) {
            bytesReceived.addAndGet(byteBuffer.remaining().toLong())
            try {
                transferBuffer.write(byteBuffer)
                bodyPipe.write(transferBuffer, transferBuffer.size)
            } catch (e: Exception) {
                // The consumer closed or canceled the pipe, or the sink deadline elapsed against
                // a body nobody drains. The rethrow reaches no terminal callback of ours, so
                // the failure has to be recorded here or the reader sees a clean EOF; the cancel
                // releases the connection and stops the base callback arming another read.
                bodyPipe.fail(if (e is IOException) e else ApifierException.Unexpected(e))
                urlRequest.get()?.cancel()
                throw e
            }
        }

        override fun onSucceeded(info: UrlResponseInfo) {
            bodyPipe.closeSink()
            reportTransfer()
        }

        override fun onFailed(info: UrlResponseInfo?, error: CronetException) {
            failCall(error.toApifierException())
        }

        override fun onCanceled(info: UrlResponseInfo?) {
            bodyPipe.closeSink()
            reportTransfer()
        }
    }
}
