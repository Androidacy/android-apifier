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

import android.os.Looper
import android.util.Log
import com.androidacy.apifier.http.Protocol as ApifierProtocol
import com.androidacy.apifier.progress.ProgressListener
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.asResponseBody
import okio.Buffer
import okio.ForwardingSource
import okio.buffer
import org.chromium.net.CronetEngine
import org.chromium.net.CronetException
import org.chromium.net.UploadDataProvider
import org.chromium.net.UploadDataSink
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** OkHttp interceptor that routes requests through a [CronetEngine] for QUIC/HTTP3 support. */
class CronetCallInterceptor(
    private val engine: CronetEngine,
    private val readTimeoutMillis: Long,
    private val executor: Executor = Executors.newCachedThreadPool { r ->
        Thread(r, "Cronet-IO").apply { isDaemon = true }
    }
) : Interceptor {

    companion object {
        private const val TAG = "CronetCallInterceptor"
        private const val READ_BUFFER_SIZE = 32 * 1024
        private const val MAX_REDIRECTS = 20
    }

    override fun intercept(chain: Interceptor.Chain): Response {
        if (Looper.getMainLooper().isCurrentThread) {
            Log.w(TAG, "HTTP request on main thread — this will block the UI and may cause ANR")
        }

        val request = chain.request()

        val headersLatch = CountDownLatch(1)
        var responseInfo: UrlResponseInfo? = null
        // Written on the Cronet callback thread, read on the consumer's reading
        // thread (including at end-of-stream, after the headers latch is released),
        // so visibility must not rely on the latch alone.
        val callbackError = AtomicReference<IOException?>()
        // The abort hook needs the request, which cannot exist before the callback that
        // builds it.
        val urlRequestRef = AtomicReference<UrlRequest?>()
        val bodyPipe = BodyPipe(readTimeoutMillis) { urlRequestRef.get()?.cancel() }
        val transferBuffer = Buffer()

        fun failRequest(e: IOException) {
            callbackError.set(e)
            bodyPipe.fail(e)
        }

        var redirectCount = 0

        val callback = object : UrlRequest.Callback() {
            override fun onRedirectReceived(
                req: UrlRequest,
                info: UrlResponseInfo,
                newLocationUrl: String
            ) {
                redirectCount++
                if (redirectCount > MAX_REDIRECTS) {
                    req.cancel()
                    failRequest(IOException("Too many redirects ($MAX_REDIRECTS)"))
                    headersLatch.countDown()
                    return
                }
                if (!newLocationUrl.startsWith("https://", ignoreCase = true)) {
                    req.cancel()
                    failRequest(IOException("Redirect to non-HTTPS URL rejected: $newLocationUrl"))
                    headersLatch.countDown()
                    return
                }
                req.followRedirect()
            }

            override fun onResponseStarted(req: UrlRequest, info: UrlResponseInfo) {
                responseInfo = info
                headersLatch.countDown()
                req.read(ByteBuffer.allocateDirect(READ_BUFFER_SIZE))
            }

            override fun onReadCompleted(
                req: UrlRequest,
                info: UrlResponseInfo,
                byteBuffer: ByteBuffer
            ) {
                byteBuffer.flip()
                try {
                    transferBuffer.write(byteBuffer)
                    bodyPipe.write(transferBuffer, transferBuffer.size)
                } catch (_: Exception) {
                    // The consumer closed (or canceled) the pipe. Cronet only
                    // advances a request via read()/cancel(), so without this the
                    // request would stay paused for the engine's lifetime, leaking
                    // the connection and the upload provider.
                    req.cancel()
                    return
                }
                byteBuffer.clear()
                req.read(byteBuffer)
            }

            override fun onSucceeded(req: UrlRequest, info: UrlResponseInfo) {
                if (responseInfo == null) {
                    responseInfo = info
                    headersLatch.countDown()
                }
                bodyPipe.closeSink()
            }

            override fun onFailed(
                req: UrlRequest,
                info: UrlResponseInfo,
                error: CronetException
            ) {
                failRequest(IOException("Cronet request failed", error))
                headersLatch.countDown()
                bodyPipe.closeSink()
            }
        }

        val urlRequest = engine.newUrlRequestBuilder(request.url.toString(), callback, executor).apply {
            setHttpMethod(request.method)

            val hasContentType = request.headers.names().any { it.equals("Content-Type", ignoreCase = true) }
            for (i in 0 until request.headers.size) {
                addHeader(request.headers.name(i), request.headers.value(i))
            }

            request.body?.let { body ->
                if (!hasContentType) {
                    body.contentType()?.let { addHeader("Content-Type", it.toString()) }
                }
                setUploadDataProvider(
                    OkHttpUploadDataProvider(body, request.tag(ProgressListener::class.java)),
                    executor
                )
            }
        }.build()

        urlRequestRef.set(urlRequest)
        urlRequest.start()

        val call = chain.call()
        while (!headersLatch.await(100, TimeUnit.MILLISECONDS)) {
            if (call.isCanceled()) {
                urlRequest.cancel()
                throw IOException("Canceled")
            }
        }

        callbackError.get()?.let { throw it }
        val info = responseInfo ?: throw IOException("No response received from Cronet")

        val assembled = ResponseAssembly.assemble(
            headers = info.allHeadersAsList.map { it.key to it.value },
            statusCode = info.httpStatusCode,
            negotiatedProtocol = info.negotiatedProtocol,
            method = request.method
        )
        val contentType = assembled.contentType?.toMediaTypeOrNull()

        val body = if (request.method == "HEAD") {
            bodyPipe.closeSink()
            Buffer().asResponseBody(contentType, 0)
        } else {
            val source = object : ForwardingSource(bodyPipe.source) {
                override fun read(sink: Buffer, byteCount: Long): Long {
                    if (call.isCanceled()) {
                        urlRequest.cancel()
                        throw IOException("Canceled")
                    }
                    return super.read(sink, byteCount)
                }
            }
            source.buffer().asResponseBody(contentType, assembled.contentLength)
        }

        val responseBuilder = Response.Builder()
            .request(request)
            .code(info.httpStatusCode)
            .message(info.httpStatusText)
            .protocol(convertProtocol(assembled.protocol))
            .body(body)

        for ((name, value) in assembled.headers) {
            responseBuilder.addHeader(name, value)
        }

        return responseBuilder.build()
    }

    private fun convertProtocol(protocol: ApifierProtocol): Protocol = when (protocol) {
        ApifierProtocol.QUIC -> Protocol.QUIC
        ApifierProtocol.HTTP_2 -> Protocol.HTTP_2
        ApifierProtocol.HTTP_1_1 -> Protocol.HTTP_1_1
        ApifierProtocol.HTTP_1_0 -> Protocol.HTTP_1_0
    }

    /**
     * Bridges OkHttp [okhttp3.RequestBody] to Cronet's [UploadDataProvider].
     *
     * The body is buffered into memory once; Cronet then pulls it in chunks via [read].
     * Upload progress is reported from those pulls, so it tracks bytes handed to the
     * transport's send buffer rather than on-wire acknowledgements. Large uploads are
     * still fully buffered — true streaming is a separate concern.
     */
    private class OkHttpUploadDataProvider(
        private val body: okhttp3.RequestBody,
        private val progressListener: ProgressListener? = null
    ) : UploadDataProvider() {

        private val data by lazy {
            val buf = Buffer()
            body.writeTo(buf)
            buf.readByteArray()
        }
        private var offset = 0

        override fun getLength(): Long = data.size.toLong()

        override fun read(uploadDataSink: UploadDataSink, byteBuffer: ByteBuffer) {
            val remaining = data.size - offset
            val toWrite = minOf(remaining, byteBuffer.remaining())
            if (toWrite > 0) {
                byteBuffer.put(data, offset, toWrite)
                offset += toWrite
            }
            progressListener?.update(offset.toLong(), data.size.toLong(), offset >= data.size)
            uploadDataSink.onReadSucceeded(false)
        }

        override fun rewind(uploadDataSink: UploadDataSink) {
            offset = 0
            progressListener?.update(0, data.size.toLong(), false)
            uploadDataSink.onRewindSucceeded()
        }
    }
}
