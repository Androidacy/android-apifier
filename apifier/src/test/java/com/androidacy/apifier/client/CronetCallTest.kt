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
import com.androidacy.apifier.http.Callback
import com.androidacy.apifier.http.ErrorCode
import com.androidacy.apifier.http.Headers
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.http.Response
import org.chromium.net.NetworkException
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException
import java.nio.ByteBuffer
import java.util.AbstractMap
import com.androidacy.apifier.http.Call as ApifierCall

@RunWith(RobolectricTestRunner::class)
class CronetCallTest {

    @Test
    fun redirectBeyondCapCancelsWithError() {
        val harness = Harness()
        harness.enqueue()

        repeat(20) { harness.cronetCallback.onRedirectReceived(harness.urlRequest, info(), "https://example.com/$it") }
        assertEquals(20, harness.urlRequest.followed)
        assertEquals(0, harness.urlRequest.canceled)

        harness.cronetCallback.onRedirectReceived(harness.urlRequest, info(), "https://example.com/last")

        assertEquals(20, harness.urlRequest.followed)
        assertEquals(1, harness.urlRequest.canceled)
        assertEquals(1, harness.callback.failures.size)
        val refusal = harness.callback.failures[0] as ApifierException.RedirectRefused
        assertTrue(refusal.reason.contains("Too many redirects"))
        assertFalse(refusal.retryable)
    }

    @Test
    fun nonHttpsRedirectRejected() {
        val harness = Harness()
        harness.enqueue()

        harness.cronetCallback.onRedirectReceived(harness.urlRequest, info(), "http://example.com/plain")

        assertEquals(0, harness.urlRequest.followed)
        assertEquals(1, harness.urlRequest.canceled)
        assertEquals(1, harness.callback.failures.size)
        val refusal = harness.callback.failures[0] as ApifierException.RedirectRefused
        assertEquals(ErrorCode.REDIRECT_REFUSED, refusal.errorCode)
        assertFalse(refusal.retryable)
    }

    @Test
    fun redirectListenerSeesHopHeaders() {
        val listener = RecordingListener()
        val harness = Harness(listener = listener)
        harness.enqueue()

        val hop = info(url = "https://hop.example.com/first", headers = listOf("Set-Cookie" to "sid=1"))
        harness.cronetCallback.onRedirectReceived(harness.urlRequest, hop, "https://example.com/second")

        assertEquals(1, harness.urlRequest.followed)
        assertEquals("https://hop.example.com/first", listener.redirects[0].first.toString())
        assertEquals("sid=1", listener.redirects[0].second["Set-Cookie"])
    }

    @Test
    fun onFailedMapsToTransportException() {
        val harness = Harness()
        harness.enqueue()

        harness.cronetCallback.onFailed(harness.urlRequest, info(), FakeNetworkException(NetworkException.ERROR_TIMED_OUT))

        assertEquals(1, harness.callback.failures.size)
        val failure = harness.callback.failures[0] as ApifierException.Transport
        assertEquals(ErrorCode.TIMED_OUT, failure.errorCode)
        assertTrue(failure.retryable)
    }

    @Test
    fun midBodyFailureReachesReaderAsError() {
        val harness = Harness()
        harness.enqueue()
        harness.cronetCallback.onResponseStarted(harness.urlRequest, info())
        val body = harness.callback.responses[0].body

        harness.readCompleted("hello")
        assertEquals("hello", body.source().readUtf8(5))

        harness.cronetCallback.onFailed(harness.urlRequest, info(), FakeNetworkException(NetworkException.ERROR_CONNECTION_RESET))

        try {
            body.source().readUtf8()
            fail("expected the transport failure instead of a clean end of stream")
        } catch (e: IOException) {
            assertEquals(ErrorCode.CONNECTION_RESET, (e as ApifierException).errorCode)
        }
        // The failure travelled the body channel because the response was already handed over.
        assertEquals(0, harness.callback.failures.size)
    }

    @Test
    fun cancelDeliversCancelledOnce() {
        val harness = Harness()
        harness.enqueue()

        harness.call.cancel()
        harness.call.cancel()

        assertEquals(1, harness.urlRequest.canceled)
        assertEquals(1, harness.callback.failures.size)
        assertTrue(harness.callback.failures[0] is ApifierException.Cancelled)
        assertTrue(harness.call.isCanceled())
    }

    @Test
    fun doubleEnqueueThrows() {
        val harness = Harness()
        harness.enqueue()

        try {
            harness.call.enqueue(RecordingCallback())
            fail("expected a single-use call to reject a second enqueue")
        } catch (_: IllegalStateException) {
            // expected
        }
    }

    @Test
    fun bytesCountedWithoutListener() {
        val listener = RecordingListener()
        val harness = Harness(listener = listener)
        harness.enqueue()
        harness.cronetCallback.onResponseStarted(harness.urlRequest, info())

        harness.readCompleted("hello ")
        harness.readCompleted("world")
        harness.cronetCallback.onSucceeded(harness.urlRequest, info())

        assertEquals(0L to 11L, listener.transfers.single())
    }

    @Test
    fun headResponseHasEmptyBody() {
        val harness = Harness(method = "HEAD")
        harness.enqueue()

        harness.cronetCallback.onResponseStarted(
            harness.urlRequest,
            info(headers = listOf("Content-Length" to "42"))
        )

        val response = harness.callback.responses.single()
        assertEquals(0L, response.body.contentLength())
        assertEquals(0, response.body.bytes().size)
    }

    @Test
    fun noContentResponseHasEmptyBody() {
        val harness = Harness()
        harness.enqueue()

        harness.cronetCallback.onResponseStarted(
            harness.urlRequest,
            info(status = 204, headers = listOf("Content-Length" to "42"))
        )

        assertEquals(0, harness.callback.responses.single().body.bytes().size)
    }

    @Test
    fun abandonedBodyCancelsRequest() {
        val harness = Harness()
        harness.enqueue()
        harness.cronetCallback.onResponseStarted(harness.urlRequest, info())

        harness.callback.responses.single().close()

        assertEquals(1, harness.urlRequest.canceled)
    }

    @Test
    fun executeBridgesAsyncResult() {
        val harness = Harness()
        harness.urlRequest.onStart = {
            harness.cronetCallback.onResponseStarted(harness.urlRequest, info())
            harness.readCompleted("ok")
            harness.cronetCallback.onSucceeded(harness.urlRequest, info())
        }

        @Suppress("DEPRECATION")
        val response = harness.call.execute()

        assertEquals(200, response.code)
        assertEquals("ok", response.body.string())
    }

    @Test
    fun executeRethrowsFailure() {
        val harness = Harness()
        harness.urlRequest.onStart = {
            harness.cronetCallback.onFailed(
                harness.urlRequest,
                info(),
                FakeNetworkException(NetworkException.ERROR_HOSTNAME_NOT_RESOLVED)
            )
        }

        try {
            @Suppress("DEPRECATION")
            harness.call.execute()
            fail("expected the transport failure to be rethrown")
        } catch (e: IOException) {
            assertEquals(ErrorCode.HOSTNAME_NOT_RESOLVED, (e as ApifierException).errorCode)
        }
    }

    @Test
    fun cancelBeforeEnqueueFailsImmediately() {
        val harness = Harness()
        harness.call.cancel()

        val callback = RecordingCallback()
        harness.call.enqueue(callback)

        assertEquals(0, harness.urlRequest.started)
        assertTrue(callback.failures.single() is ApifierException.Cancelled)
    }

    private class Harness(
        method: String = "GET",
        listener: TransportListener? = null
    ) {
        val urlRequest = FakeUrlRequest()
        val callback = RecordingCallback()
        lateinit var cronetCallback: UrlRequest.Callback

        val call = CronetCall(
            Request.Builder().url("https://example.com/").method(method, null).build(),
            5_000L,
            listener
        ) { cronetCallback, _ ->
            this.cronetCallback = cronetCallback
            urlRequest
        }

        fun enqueue() = call.enqueue(callback)

        fun readCompleted(text: String) {
            val bytes = text.toByteArray()
            val buffer = ByteBuffer.allocateDirect(32 * 1024)
            buffer.put(bytes)
            cronetCallback.onReadCompleted(urlRequest, info(), buffer)
        }
    }

    private class FakeUrlRequest : UrlRequest() {
        var started = 0
        var canceled = 0
        var followed = 0
        var onStart: (() -> Unit)? = null

        override fun start() {
            started++
            onStart?.let { script -> Thread(script).apply { isDaemon = true }.start() }
        }

        override fun followRedirect() {
            followed++
        }

        override fun read(buffer: ByteBuffer) = Unit

        override fun cancel() {
            canceled++
        }

        override fun isDone(): Boolean = false

        override fun getStatus(listener: StatusListener) = Unit
    }

    private class FakeNetworkException(private val code: Int) : NetworkException("fake cronet failure", IOException("socket")) {
        override fun getErrorCode(): Int = code

        override fun getCronetInternalErrorCode(): Int = -100

        override fun immediatelyRetryable(): Boolean = false
    }

    private class RecordingCallback : Callback {
        val responses = mutableListOf<Response>()
        val failures = mutableListOf<IOException>()

        override fun onResponse(call: ApifierCall, response: Response) {
            responses += response
        }

        override fun onFailure(call: ApifierCall, e: IOException) {
            failures += e
        }
    }

    private class RecordingListener : TransportListener {
        val redirects = mutableListOf<Pair<Uri, Headers>>()
        val ttfb = mutableListOf<Long>()
        val transfers = mutableListOf<Pair<Long, Long>>()

        override fun onRedirect(hopUri: Uri, hopHeaders: Headers) {
            redirects += hopUri to hopHeaders
        }

        override fun onResponseStarted(ttfbMillis: Long) {
            ttfb += ttfbMillis
        }

        override fun onTransferComplete(bytesSent: Long, bytesReceived: Long) {
            transfers += bytesSent to bytesReceived
        }
    }

    private companion object {
        fun info(
            status: Int = 200,
            url: String = "https://example.com/",
            headers: List<Pair<String, String>> = emptyList(),
            negotiatedProtocol: String = "h2"
        ) = FakeUrlResponseInfo(status, url, headers, negotiatedProtocol)
    }

    private class FakeUrlResponseInfo(
        private val status: Int,
        private val url: String,
        private val headers: List<Pair<String, String>>,
        private val negotiatedProtocol: String
    ) : UrlResponseInfo() {
        override fun getUrl(): String = url

        override fun getUrlChain(): List<String> = listOf(url)

        override fun getHttpStatusCode(): Int = status

        override fun getHttpStatusText(): String = "OK"

        override fun wasCached(): Boolean = false

        override fun getNegotiatedProtocol(): String = negotiatedProtocol

        override fun getProxyServer(): String = ""

        override fun getReceivedByteCount(): Long = 0L

        override fun getAllHeadersAsList(): List<Map.Entry<String, String>> =
            headers.map { AbstractMap.SimpleEntry(it.first, it.second) }

        override fun getAllHeaders(): Map<String, List<String>> =
            headers.groupBy({ it.first }, { it.second })
    }
}
