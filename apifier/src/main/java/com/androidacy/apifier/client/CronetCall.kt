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
import android.os.Looper
import android.util.Log
import com.androidacy.apifier.http.ApifierException
import com.androidacy.apifier.http.Call
import com.androidacy.apifier.http.Callback
import com.androidacy.apifier.http.Headers
import com.androidacy.apifier.http.MediaType.Companion.toMediaTypeOrNull
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.http.Response
import com.androidacy.apifier.http.ResponseBody.Companion.asResponseBody
import com.androidacy.apifier.http.ResponseBody.Companion.toResponseBody
import com.androidacy.apifier.http.toApifierException
import okio.Buffer
import okio.buffer
import org.chromium.net.CronetException
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

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
 * One attempt at [request], run on a Cronet engine.
 *
 * The callback delivery and the body stream are separate: [Callback] fires as soon as the
 * headers arrive, and the body flows through a [BodyPipe] afterwards, so a failure partway
 * through the body reaches the reader rather than the callback.
 */
internal class CronetCall(
    private val request: Request,
    readTimeoutMs: Long,
    private val listener: TransportListener?,
    private val urlRequestFactory: UrlRequestFactory
) : Call {

    private companion object {
        const val TAG = "CronetCall"
        const val READ_BUFFER_SIZE = 32 * 1024
        const val MAX_REDIRECTS = 20
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
    private var callback: Callback? = null

    @Volatile
    private var startNanos = 0L

    private var redirectCount = 0

    override fun request(): Request = request

    override fun enqueue(callback: Callback) {
        check(enqueued.compareAndSet(false, true)) { "Call already enqueued" }
        this.callback = callback

        if (canceled.get()) {
            deliverFailure(ApifierException.Cancelled())
            return
        }

        val started = urlRequestFactory.create(cronetCallback, bytesSent)
        urlRequest.set(started)
        startNanos = System.nanoTime()
        started.start()
        // A cancel that arrived before the request existed found nothing to cancel.
        if (canceled.get()) started.cancel()
    }

    @Deprecated("Blocking bridge over the async path; prefer enqueue.")
    override fun execute(): Response {
        if (Looper.getMainLooper().isCurrentThread) {
            Log.w(TAG, "HTTP request on main thread; this will block the UI and may cause ANR")
        }

        val done = CountDownLatch(1)
        val result = AtomicReference<Response?>()
        val failure = AtomicReference<IOException?>()
        enqueue(object : Callback {
            override fun onResponse(call: Call, response: Response) {
                result.set(response)
                done.countDown()
            }

            override fun onFailure(call: Call, e: IOException) {
                failure.set(e)
                done.countDown()
            }
        })

        done.await()
        failure.get()?.let { throw it }
        return checkNotNull(result.get())
    }

    override fun cancel() {
        if (!canceled.compareAndSet(false, true)) return
        urlRequest.get()?.cancel()
        val cancellation = ApifierException.Cancelled()
        bodyPipe.fail(cancellation)
        deliverFailure(cancellation)
    }

    override fun isCanceled(): Boolean = canceled.get()

    private fun deliverResponse(response: Response) {
        val target = callback ?: return
        if (delivered.compareAndSet(false, true)) target.onResponse(this, response)
    }

    private fun deliverFailure(e: IOException) {
        val target = callback ?: return
        if (delivered.compareAndSet(false, true)) target.onFailure(this, e)
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

    private val cronetCallback = object : UrlRequest.Callback() {

        override fun onRedirectReceived(req: UrlRequest, info: UrlResponseInfo, newLocationUrl: String) {
            redirectCount++
            val refusal = when {
                redirectCount > MAX_REDIRECTS -> "Too many redirects ($MAX_REDIRECTS)"
                !newLocationUrl.startsWith("https://", ignoreCase = true) ->
                    "Redirect to non-HTTPS URL rejected: $newLocationUrl"
                else -> null
            }
            if (refusal != null) {
                req.cancel()
                failCall(ApifierException.RedirectRefused(refusal))
                return
            }

            listener?.onRedirect(
                Uri.parse(info.url),
                Headers.of(info.allHeadersAsList.map { it.key to it.value })
            )
            req.followRedirect()
        }

        override fun onResponseStarted(req: UrlRequest, info: UrlResponseInfo) {
            listener?.onResponseStarted((System.nanoTime() - startNanos) / 1_000_000)

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

            // Cronet only advances a request through read() or cancel(). A bodyless response
            // still needs the read so the engine reaches its terminal state.
            req.read(ByteBuffer.allocateDirect(READ_BUFFER_SIZE))

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

        override fun onReadCompleted(req: UrlRequest, info: UrlResponseInfo, byteBuffer: ByteBuffer) {
            byteBuffer.flip()
            bytesReceived.addAndGet(byteBuffer.remaining().toLong())
            try {
                transferBuffer.write(byteBuffer)
                bodyPipe.write(transferBuffer, transferBuffer.size)
            } catch (_: Exception) {
                // The consumer closed or canceled the pipe. Without the cancel the request would
                // stay paused for the engine's lifetime, leaking the connection and the upload
                // provider.
                req.cancel()
                return
            }
            byteBuffer.clear()
            req.read(byteBuffer)
        }

        override fun onSucceeded(req: UrlRequest, info: UrlResponseInfo) {
            bodyPipe.closeSink()
            reportTransfer()
        }

        override fun onFailed(req: UrlRequest, info: UrlResponseInfo, error: CronetException) {
            failCall(error.toApifierException())
        }

        override fun onCanceled(req: UrlRequest, info: UrlResponseInfo) {
            bodyPipe.closeSink()
            reportTransfer()
        }
    }
}
