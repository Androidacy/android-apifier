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

import android.content.Context
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import com.androidacy.apifier.http.ApifierException
import com.androidacy.apifier.http.Call
import com.androidacy.apifier.http.Callback
import com.androidacy.apifier.http.Headers
import com.androidacy.apifier.http.Protocol
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.http.Response
import com.androidacy.apifier.http.ResponseBody.Companion.toResponseBody
import com.androidacy.apifier.observe.Outcome
import com.androidacy.apifier.observe.RequestEvent
import com.androidacy.apifier.observe.RequestObserver
import com.androidacy.apifier.progress.Progress
import kotlinx.coroutines.flow.MutableSharedFlow
import org.chromium.net.CronetProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.shadows.ShadowLog
import java.io.IOException
import java.net.ServerSocket
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

@RunWith(RobolectricTestRunner::class)
class ApifierClientTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    fun helpersBuildEquivalentRequests() {
        val engine = FakeEngine()
        val client = clientOf(engine)
        val file = temporaryFolder.newFile("payload.bin").apply { writeBytes(ByteArray(4)) }
        val progress = MutableSharedFlow<Progress>(extraBufferCapacity = 8)
        val done = CountDownLatch(6)
        val callback = countingCallback(done)

        client.get(URL, callback)
        client.post(URL, "{}", callback = callback)
        client.delete(URL, callback)
        client.head(URL, callback)
        client.download(URL, progress, callback)
        client.upload(URL, listOf(file), listOf("field"), progress, callback)

        assertTrue(done.await(10, TimeUnit.SECONDS))
        client.close()

        val seen = engine.seen.associateBy { request ->
            request.method + if (request.tag(ProgressSink::class.java) == null) "" else "+p"
        }
        assertEquals(setOf("GET", "POST", "DELETE", "HEAD", "GET+p", "POST+p"), seen.keys)
        assertEquals("application/json", seen.getValue("POST").body?.contentType()?.toString())
        assertNull(seen.getValue("GET").body)
        assertTrue(
            seen.getValue("POST+p").body?.contentType()?.toString().orEmpty()
                .startsWith("multipart/form-data")
        )
    }

    @Test
    fun noRetryTagLimitsAttempts() {
        val engine = FakeEngine(respond = { serverError(it) })
        val client = clientOf(engine, NetworkConfig(retryConfig = RetryConfig(maxAttempts = 2)))

        val retried = CountDownLatch(1)
        client.get(URL, countingCallback(retried))
        assertTrue(retried.await(10, TimeUnit.SECONDS))
        assertEquals(2, engine.seen.size)

        val notRetried = CountDownLatch(1)
        val request = Request.Builder().url(URL).noRetry().get().build()
        client.call(request).enqueue(countingCallback(notRetried))
        assertTrue(notRetried.await(10, TimeUnit.SECONDS))
        assertEquals(3, engine.seen.size)

        client.close()
    }

    @Test
    fun closeCancelsInFlightCallsBeforeStoppingTheEngine() {
        val engine = FakeEngine(hang = true)
        val client = clientOf(engine)
        val outcome = AtomicReference<Throwable?>()
        val done = CountDownLatch(1)
        client.get(
            URL,
            object : Callback {
                override fun onResponse(call: Call, response: Response) {
                    response.close()
                    done.countDown()
                }

                override fun onFailure(call: Call, e: IOException) {
                    outcome.set(e)
                    done.countDown()
                }
            }
        )
        assertTrue("call never reached the engine", engine.started.await(10, TimeUnit.SECONDS))

        val startedAt = System.nanoTime()
        client.close()
        val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000

        assertTrue("close took ${elapsedMs}ms", elapsedMs < 5_000)
        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertTrue("got ${outcome.get()}", outcome.get() is ApifierException.Cancelled)
        assertEquals(listOf("cancel", "shutdown"), engine.log)
    }

    @Test
    fun closeDeliversObservationEventsFromItsOwnCancellations() {
        val engine = FakeEngine(hang = true)
        val client = clientOf(engine)
        val events = Collections.synchronizedList(mutableListOf<RequestEvent>())
        client.addObserver { events.add(it) }
        val done = CountDownLatch(1)
        client.get(URL, countingCallback(done))
        assertTrue(engine.started.await(10, TimeUnit.SECONDS))

        client.close()

        assertEquals(1, events.size)
        assertEquals(Outcome.FAILED, events[0].outcome)
        assertTrue(done.await(5, TimeUnit.SECONDS))
    }

    @Test
    fun closeIsIdempotentAndCallsAfterCloseFail() {
        val engine = FakeEngine()
        val client = clientOf(engine)
        val prepared = client.call(Request.Builder().url(URL).get().build())

        client.close()
        client.close()

        assertEquals(listOf("shutdown"), engine.log)
        assertThrows(IllegalStateException::class.java) {
            client.call(Request.Builder().url(URL).get().build())
        }
        // A call handed out before close still holds a scheduler and an engine that are gone.
        assertThrows(IllegalStateException::class.java) {
            prepared.enqueue(countingCallback(CountDownLatch(1)))
        }
        assertThrows(IllegalStateException::class.java) {
            @Suppress("DEPRECATION")
            prepared.execute()
        }
    }

    @Test
    fun closeReachesACallWhoseBodyOutlivedItsCallback() {
        val engine = FakeEngine()
        val client = clientOf(engine)
        val streaming = AtomicReference<Response?>()
        val delivered = CountDownLatch(1)
        client.get(
            URL,
            object : Callback {
                override fun onResponse(call: Call, response: Response) {
                    streaming.set(response)
                    delivered.countDown()
                }

                override fun onFailure(call: Call, e: IOException) = delivered.countDown()
            }
        )
        assertTrue(delivered.await(10, TimeUnit.SECONDS))
        thread(isDaemon = true) {
            Thread.sleep(300)
            streaming.get()?.close()
        }

        val startedAt = System.nanoTime()
        client.close()
        val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000

        assertEquals(listOf("cancel", "shutdown"), engine.log)
        assertTrue("close returned after ${elapsedMs}ms", elapsedMs in 250..4_000)
    }

    @Test
    fun closeFromAClientCallbackIsRefused() {
        val engine = FakeEngine()
        val client = clientOf(engine)
        val thrown = AtomicReference<Throwable?>()
        val done = CountDownLatch(1)
        client.get(
            URL,
            object : Callback {
                override fun onResponse(call: Call, response: Response) {
                    response.close()
                    thrown.set(runCatching { client.close() }.exceptionOrNull())
                    done.countDown()
                }

                override fun onFailure(call: Call, e: IOException) = done.countDown()
            }
        )

        assertTrue(done.await(10, TimeUnit.SECONDS))
        assertTrue("got ${thrown.get()}", thrown.get() is IllegalStateException)
        client.close()
        assertEquals(listOf("shutdown"), engine.log)
    }

    @Test
    fun closeFinishesEveryStepWhenOneThrows() {
        val engine = FakeEngine(shutdownThrows = true)
        val client = clientOf(engine)
        val events = Collections.synchronizedList(mutableListOf<RequestEvent>())
        client.addObserver { events.add(it) }
        val done = CountDownLatch(1)
        client.get(URL, countingCallback(done))
        assertTrue(done.await(10, TimeUnit.SECONDS))

        client.close()

        assertEquals(listOf("shutdown"), engine.log)
        assertEquals(1, events.size)
    }

    @Test
    fun observerRegistrationRoundTrips() {
        val engine = FakeEngine()
        val client = clientOf(engine)
        val kept = mutableListOf<RequestEvent>()
        val dropped = mutableListOf<RequestEvent>()
        val keptObserver = RequestObserver { kept.add(it) }
        val droppedObserver = RequestObserver { dropped.add(it) }
        client.addObserver(keptObserver)
        client.addObserver(droppedObserver)
        client.removeObserver(droppedObserver)

        val done = CountDownLatch(1)
        client.get(URL, countingCallback(done))
        assertTrue(done.await(10, TimeUnit.SECONDS))
        client.close()

        assertEquals(1, kept.size)
        assertEquals(Outcome.SUCCESS, kept[0].outcome)
        assertTrue(dropped.isEmpty())
    }

    @Test
    fun breakerRegistryEvictsBeyondItsBound() {
        val config = CircuitBreakerConfig(failureThreshold = 1)
        val evicting = BreakerRegistry(config)
        checkNotNull(evicting.forHost("host-0")).recordFailure()
        repeat(64) { checkNotNull(evicting.forHost("host-${it + 1}")) }

        assertTrue("the oldest host was kept", checkNotNull(evicting.forHost("host-0")).isClosed)

        val withinBound = BreakerRegistry(config)
        checkNotNull(withinBound.forHost("host-0")).recordFailure()
        repeat(63) { checkNotNull(withinBound.forHost("host-${it + 1}")) }

        assertTrue(checkNotNull(withinBound.forHost("host-0")).isOpen)
    }

    /**
     * The one close path that runs against real Cronet objects. The Java fallback engine accepts
     * `shutdown` even with an active request, so this cannot tell engine-first from pool-first;
     * it fails when close throws or hangs.
     */
    @Test
    fun liveEngineShutdownEndsWithoutThrowingOrHanging() {
        val provider = Class.forName("org.chromium.net.impl.JavaCronetProvider")
            .getConstructor(Context::class.java)
            .newInstance(context) as CronetProvider
        val cronet = provider.createBuilder().build()
        val engine = CronetClientEngine(cronet, emptyMap(), READ_TIMEOUT_MS)
        val server = ServerSocket(0)
        thread(isDaemon = true) { runCatching { server.accept() } }
        val client = ApifierClient(context, NetworkConfig(), engine)

        val done = CountDownLatch(1)
        client.get("https://127.0.0.1:${server.localPort}/", countingCallback(done))
        assertFalse(
            "the call finished before close, so nothing was in flight",
            done.await(500, TimeUnit.MILLISECONDS)
        )

        val startedAt = System.nanoTime()
        client.close()
        val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000
        server.close()

        assertTrue("close took ${elapsedMs}ms", elapsedMs < 10_000)
        assertTrue(done.await(5, TimeUnit.SECONDS))
    }

    @Test
    fun blockingExecuteOnTheMainThreadWarns() {
        val engine = FakeEngine()
        val client = clientOf(engine)
        ShadowLog.clear()

        @Suppress("DEPRECATION")
        client.call(Request.Builder().url(URL).get().build()).execute().close()
        assertEquals(1, ShadowLog.getLogs().count { it.type == Log.WARN && "main thread" in it.msg })

        val worker = thread(isDaemon = true) {
            @Suppress("DEPRECATION")
            client.call(Request.Builder().url(URL).get().build()).execute().close()
        }
        worker.join(10_000)

        assertEquals(
            "a worker thread is not the UI thread",
            1,
            ShadowLog.getLogs().count { it.type == Log.WARN && "main thread" in it.msg }
        )
        client.close()
    }

    @Test
    fun nonIoTransportFailureSurfacesAsApifierExceptionOnBothPaths() {
        val engine = FakeEngine(newCallThrows = IllegalStateException("engine went sideways"))
        val client = clientOf(engine)

        val thrown = assertThrows(ApifierException.Unexpected::class.java) {
            @Suppress("DEPRECATION")
            client.call(Request.Builder().url(URL).get().build()).execute()
        }
        assertEquals("engine went sideways", thrown.cause?.message)

        val delivered = AtomicReference<IOException?>()
        val done = CountDownLatch(1)
        client.get(
            URL,
            object : Callback {
                override fun onResponse(call: Call, response: Response) = done.countDown()

                override fun onFailure(call: Call, e: IOException) {
                    delivered.set(e)
                    done.countDown()
                }
            }
        )
        assertTrue(done.await(10, TimeUnit.SECONDS))

        assertTrue("got ${delivered.get()}", delivered.get() is ApifierException.Unexpected)
        assertEquals("engine went sideways", delivered.get()?.cause?.message)
        client.close()
    }

    private fun clientOf(engine: FakeEngine, config: NetworkConfig = NetworkConfig()) =
        ApifierClient(context, config, engine)

    private fun countingCallback(latch: CountDownLatch) = object : Callback {
        override fun onResponse(call: Call, response: Response) {
            response.close()
            latch.countDown()
        }

        override fun onFailure(call: Call, e: IOException) = latch.countDown()
    }

    private fun serverError(request: Request): Response = response(request, 500)

    private fun response(request: Request, code: Int = 200): Response = Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_2)
        .code(code)
        .message("")
        .headers(Headers.headersOf())
        .body(ByteArray(0).toResponseBody(null))
        .build()

    /** Records the teardown order the client drives, and every request that reached it. */
    private inner class FakeEngine(
        private val hang: Boolean = false,
        private val shutdownThrows: Boolean = false,
        private val newCallThrows: Throwable? = null,
        private val respond: (Request) -> Response = { response(it) }
    ) : ClientEngine {

        val seen: List<Request> get() = synchronized(requests) { requests.toList() }
        val log: List<String> get() = synchronized(entries) { entries.toList() }
        val started = CountDownLatch(1)

        private val requests = mutableListOf<Request>()
        private val entries = mutableListOf<String>()

        override val provider = "fake"
        override val providerReport = mapOf("fake:1" to HttpClientBuilder.PROVIDER_IN_USE)

        override fun newCall(request: Request, listener: TransportListener?): AttemptCall {
            synchronized(requests) { requests.add(request) }
            newCallThrows?.let { throw it }
            return FakeCall(request, listener)
        }

        override fun shutdown() {
            record("shutdown")
            if (shutdownThrows) throw IllegalStateException("engine refused")
        }

        fun record(entry: String) {
            synchronized(entries) { entries.add(entry) }
        }

        /**
         * Mirrors the transport contract: exactly one terminal callback, a prompt cancel, and
         * byte counting unconditional on and after delivery, the ordering the real transport has.
         */
        private inner class FakeCall(
            private val request: Request,
            private val listener: TransportListener?
        ) : AttemptCall {

            private val canceled = AtomicBoolean(false)
            private val delivered = AtomicBoolean(false)
            private val cancelSignal = CountDownLatch(1)

            override fun request(): Request = request

            override fun enqueue(callback: Callback) {
                thread(isDaemon = true) {
                    started.countDown()
                    if (hang) cancelSignal.await(30, TimeUnit.SECONDS)
                    if (canceled.get()) {
                        deliver { callback.onFailure(this, ApifierException.Cancelled()) }
                    } else {
                        listener?.onResponseStarted(0, request.uri)
                        deliver { callback.onResponse(this, respond(request)) }
                    }
                    listener?.onTransferComplete(0, 0)
                }
            }

            override suspend fun await(): Response = throw UnsupportedOperationException()

            @Deprecated("Blocking bridge over the async path; prefer enqueue.")
            override fun execute(): Response = throw UnsupportedOperationException()

            override fun cancel() {
                if (!canceled.compareAndSet(false, true)) return
                record("cancel")
                cancelSignal.countDown()
            }

            override fun isCanceled(): Boolean = canceled.get()

            private fun deliver(outcome: () -> Unit) {
                if (delivered.compareAndSet(false, true)) outcome()
            }
        }
    }

    private companion object {
        const val URL = "https://api.example.com/resource"
        const val READ_TIMEOUT_MS = 5_000L
    }
}
