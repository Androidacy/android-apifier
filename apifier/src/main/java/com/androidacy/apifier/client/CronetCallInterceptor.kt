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

import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.asResponseBody
import okio.Buffer
import okio.Pipe
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

/**
 * OkHttp interceptor that routes requests through a [CronetEngine], providing
 * QUIC/HTTP3, HTTP/2, and Brotli support. Response bodies are streamed through
 * an Okio [Pipe] so callers can begin reading before the full response arrives.
 */
class CronetCallInterceptor(
    private val engine: CronetEngine,
    private val executor: Executor = Executors.newCachedThreadPool { r ->
        Thread(r, "Cronet-IO").apply { isDaemon = true }
    }
) : Interceptor {

    companion object {
        private const val READ_BUFFER_SIZE = 32 * 1024 // 32KB
        private const val PIPE_BUFFER_SIZE = 256L * 1024 // 256KB
        private val ENCODINGS_HANDLED_BY_CRONET = setOf("br", "deflate", "gzip", "x-gzip")
    }

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()

        val headersLatch = CountDownLatch(1)
        var responseInfo: UrlResponseInfo? = null
        var callbackError: IOException? = null
        val pipe = Pipe(PIPE_BUFFER_SIZE)
        val transferBuffer = Buffer()

        val callback = object : UrlRequest.Callback() {
            override fun onRedirectReceived(
                req: UrlRequest,
                info: UrlResponseInfo,
                newLocationUrl: String
            ) {
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
                    pipe.sink.write(transferBuffer, transferBuffer.size)
                    pipe.sink.flush()
                } catch (_: Exception) {
                    return // pipe closed by consumer
                }
                byteBuffer.clear()
                req.read(byteBuffer)
            }

            override fun onSucceeded(req: UrlRequest, info: UrlResponseInfo) {
                if (responseInfo == null) {
                    responseInfo = info
                    headersLatch.countDown()
                }
                try { pipe.sink.close() } catch (_: Exception) {}
            }

            override fun onFailed(
                req: UrlRequest,
                info: UrlResponseInfo?,
                error: CronetException
            ) {
                callbackError = IOException("Cronet request failed", error)
                headersLatch.countDown()
                try { pipe.sink.close() } catch (_: Exception) {}
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
                setUploadDataProvider(OkHttpUploadDataProvider(body), executor)
            }
        }.build()

        urlRequest.start()

        val call = chain.call()
        while (!headersLatch.await(100, TimeUnit.MILLISECONDS)) {
            if (call.isCanceled()) {
                urlRequest.cancel()
                throw IOException("Canceled")
            }
        }

        callbackError?.let { throw it }
        val info = responseInfo ?: throw IOException("No response received from Cronet")

        // Cronet natively decodes certain encodings. When it does, the original
        // Content-Encoding and Content-Length headers are no longer accurate.
        val contentEncodings = (info.allHeaders["Content-Encoding"] ?: emptyList())
            .flatMap { it.split(",").map(String::trim).filter(String::isNotEmpty) }
        val cronetDecodedBody = contentEncodings.isNotEmpty() &&
            ENCODINGS_HANDLED_BY_CRONET.containsAll(contentEncodings)

        val contentType = info.allHeaders["Content-Type"]?.lastOrNull()
        val contentLength = if (cronetDecodedBody || request.method == "HEAD") {
            -1L
        } else {
            info.allHeaders["Content-Length"]?.lastOrNull()?.toLongOrNull() ?: -1L
        }

        val body = if (request.method == "HEAD") {
            try { pipe.sink.close() } catch (_: Exception) {}
            Buffer().asResponseBody(contentType?.toMediaTypeOrNull(), 0)
        } else {
            pipe.source.buffer().asResponseBody(contentType?.toMediaTypeOrNull(), contentLength)
        }

        val responseBuilder = Response.Builder()
            .request(request)
            .code(info.httpStatusCode)
            .message(info.httpStatusText)
            .protocol(convertProtocol(info.negotiatedProtocol))
            .body(body)

        for ((name, value) in info.allHeadersAsList) {
            if (cronetDecodedBody && name.equals("Content-Encoding", ignoreCase = true)) continue
            if (cronetDecodedBody && name.equals("Content-Length", ignoreCase = true)) continue
            responseBuilder.addHeader(name, value)
        }

        return responseBuilder.build()
    }

    private fun convertProtocol(negotiatedProtocol: String): Protocol = when {
        negotiatedProtocol.contains("h3") || negotiatedProtocol.contains("quic") -> Protocol.QUIC
        negotiatedProtocol.contains("h2") || negotiatedProtocol.contains("spdy") -> Protocol.HTTP_2
        negotiatedProtocol.contains("http/1.1") -> Protocol.HTTP_1_1
        else -> Protocol.HTTP_1_0
    }

    /**
     * Bridges OkHttp [okhttp3.RequestBody] to Cronet's [UploadDataProvider].
     */
    private class OkHttpUploadDataProvider(
        private val body: okhttp3.RequestBody
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
            uploadDataSink.onReadSucceeded(false)
        }

        override fun rewind(uploadDataSink: UploadDataSink) {
            offset = 0
            uploadDataSink.onRewindSucceeded()
        }
    }
}
