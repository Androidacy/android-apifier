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
import android.net.ConnectivityManager
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import com.androidacy.apifier.dns.ResolverQualification
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
import com.androidacy.apifier.security.CookieStorage
import com.androidacy.apifier.security.InMemoryCookieStorage
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExecutorCoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.suspendCancellableCoroutine
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
import org.robolectric.Shadows.shadowOf
import org.robolectric.shadows.ShadowLog
import org.robolectric.shadows.ShadowNetwork
import java.io.Closeable
import java.io.IOException
import java.net.ServerSocket
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.coroutines.resumeWithException
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

@RunWith(RobolectricTestRunner::class)
class ApifierClientTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    @Suppress("DEPRECATION")
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

    /** Fails if the builder's default reaches only [ApifierClient.maxAttempts]'s derived views, not a plain [ApifierClient.send]. */
    @Test
    fun builderDefaultAppliesToEveryCall() {
        val engine = FakeEngine(respond = { serverError(it) })
        val config = NetworkConfigBuilder().apply { maxAttempts(2) }.build()
        val client = clientOf(engine, config)

        val response = runBlocking { client.get(URL) }

        assertEquals(2, engine.seen.size)
        response.close()
        client.close()
    }

    /** Production change that fails this: dropping the header option from [Pipeline.prepare]. */
    @Test
    fun aPerCallHeaderReachesTheTransport() {
        val engine = FakeEngine()
        val client = clientOf(engine)

        val response = runBlocking { client.header("X-Trace", "abc").get(URL) }

        assertEquals("abc", engine.seen.single().header("X-Trace"))
        response.close()
        client.close()
    }

    /** Production change that fails this: applying [NetworkConfig.headers] after per-call headers. */
    @Test
    fun aPerCallHeaderOverridesTheClientWideOne() {
        val engine = FakeEngine()
        val config = NetworkConfigBuilder().apply { header("X-Trace", "global") }.build()
        val client = clientOf(engine, config)

        val response = runBlocking { client.header("X-Trace", "per-call").get(URL) }

        assertEquals("per-call", engine.seen.single().header("X-Trace"))
        response.close()
        client.close()
    }

    /** Production change that fails this: reversing the precedence between a request header and a per-call one. */
    @Test
    fun aRequestHeaderOverridesAPerCallOne() {
        val engine = FakeEngine()
        val client = clientOf(engine)
        val request = Request.Builder().url(URL).header("X-Trace", "on-request").get().build()

        val response = runBlocking { client.header("X-Trace", "per-call").send(request) }

        assertEquals("on-request", engine.seen.single().header("X-Trace"))
        response.close()
        client.close()
    }

    /** Production change that fails this: storing the per-call header on the client instead of the derived view. */
    @Test
    fun aPerCallHeaderDoesNotLeakToOtherCalls() {
        val engine = FakeEngine()
        val client = clientOf(engine)

        val first = runBlocking { client.header("X-Trace", "abc").get(URL) }
        val second = runBlocking { client.get(URL) }

        assertNull(engine.seen[1].header("X-Trace"))
        first.close()
        second.close()
        client.close()
    }

    /** Production change that fails this: bypassing header validation for the per-call value. */
    @Test
    fun anInvalidPerCallHeaderValueIsRejected() {
        val client = clientOf(FakeEngine())

        assertThrows(IllegalArgumentException::class.java) {
            client.header("X-Trace", "line1\nline2")
        }

        client.close()
    }

    /** Fails if the builder default is read instead of the derived view's override. */
    @Test
    fun perCallModifierOverridesTheBuilderDefault() {
        val engine = FakeEngine(respond = { serverError(it) })
        val config = NetworkConfigBuilder().apply { maxAttempts(2) }.build()
        val client = clientOf(engine, config)

        val response = runBlocking { client.maxAttempts(3).get(URL) }

        assertEquals(3, engine.seen.size)
        response.close()
        client.close()
    }

    /** Fails if the builder's timeout is applied unconditionally, ignoring a per-call override. */
    @Test
    fun builderTimeoutIsOverriddenPerCall() {
        val engine = FakeEngine(hang = true)
        val config = NetworkConfigBuilder().apply { timeout(20.seconds) }.build()
        val client = clientOf(engine, config)

        val thrown = assertThrows(ApifierException.CallTimeout::class.java) {
            runBlocking { client.timeout(200.milliseconds).get(URL) }
        }

        assertEquals("the builder's timeout was used instead of the override", 200L, thrown.timeoutMillis)
        client.close()
    }

    /** Fails if `retry { }` resets a ceiling set through the top-level [NetworkConfigBuilder.maxAttempts]. */
    @Test
    fun nestedRetryBlockDoesNotResetTheTopLevelMaxAttempts() {
        val engine = FakeEngine(respond = { serverError(it) })
        val config = NetworkConfigBuilder().apply {
            maxAttempts(2)
            retry { retryOn5xx = true }
        }.build()
        val client = clientOf(engine, config)

        val response = runBlocking { client.get(URL) }

        assertEquals(2, engine.seen.size)
        response.close()
        client.close()
    }

    /** Fails if `timeouts { }` resets a budget set through the top-level [NetworkConfigBuilder.timeout]. */
    @Test
    fun nestedTimeoutsBlockDoesNotResetTheTopLevelTimeout() {
        val engine = FakeEngine(hang = true)
        val config = NetworkConfigBuilder().apply {
            timeout(200.milliseconds)
            timeouts { read = 5.seconds }
        }.build()
        val client = clientOf(engine, config)

        val thrown = assertThrows(ApifierException.CallTimeout::class.java) {
            runBlocking { client.get(URL) }
        }

        assertEquals("the nested block reset the top-level timeout", 200L, thrown.timeoutMillis)
        client.close()
    }

    /** Fails if the [NetworkConfigBuilder.observe] default is dropped anywhere between the builder and the terminal event. */
    @Test
    fun builderObserveReceivesTheTerminalEventWhenNoCallSetsOne() {
        val engine = FakeEngine()
        val events = Collections.synchronizedList(mutableListOf<RequestEvent>())
        val config = NetworkConfigBuilder().apply { observe { events.add(it) } }.build()
        val client = clientOf(engine, config)

        runBlocking { client.get(URL).close() }
        client.close()

        assertEquals(1, events.size)
        assertEquals(Outcome.SUCCESS, events[0].outcome)
    }

    @Test
    @Suppress("DEPRECATION")
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
    @Suppress("DEPRECATION")
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
    @Suppress("DEPRECATION")
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
            prepared.execute()
        }
    }

    @Test
    @Suppress("DEPRECATION")
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

    /** Production change that fails this: dropping the settle from the pipeline's timeout task. */
    @Test
    fun anAbandonedBodyIsDeregisteredWhenTheBudgetExpires() {
        val engine = FakeEngine()
        val client = clientOf(engine, NetworkConfig(timeouts = TimeoutConfig(call = 200.milliseconds)))
        runBlocking { client.send(getRequest()) }
        Thread.sleep(600)

        val startedAt = System.nanoTime()
        client.close()
        val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000

        // A call still counted as in flight holds close() in its drain for the full 5s timeout.
        assertTrue("close returned after ${elapsedMs}ms", elapsedMs < 2_000)
    }

    @Test
    @Suppress("DEPRECATION")
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

    /** Production change that fails this: dropping the callback marker from observation dispatch. */
    @Test
    @Suppress("DEPRECATION")
    fun closeFromAnObserverIsRefused() {
        val client = clientOf(FakeEngine())
        val thrown = AtomicReference<Throwable?>()
        val attempted = CountDownLatch(1)
        client.addObserver {
            thrown.set(runCatching { client.close() }.exceptionOrNull())
            attempted.countDown()
        }

        runBlocking { client.get(URL).close() }

        assertTrue("the observer never ran", attempted.await(10, TimeUnit.SECONDS))
        assertTrue("got ${thrown.get()}", thrown.get() is IllegalStateException)
        client.close()
    }

    /**
     * A refused close runs no teardown step, which is what keeps it prompt. Production change that
     * fails this: letting close() reach the observation join from the collector's own thread, where
     * it spends the close timeout after shutting the engine down on the way there.
     */
    @Test
    @Suppress("DEPRECATION")
    fun closeFromAnObserverDoesNotHang() {
        val engine = FakeEngine()
        val client = clientOf(engine)
        val attempted = CountDownLatch(1)
        client.addObserver {
            runCatching { client.close() }
            attempted.countDown()
        }

        runBlocking { client.get(URL).close() }

        assertTrue("the observer never ran", attempted.await(10, TimeUnit.SECONDS))
        assertTrue("close ran teardown: ${engine.log}", engine.log.isEmpty())
        client.close()
    }

    /** Production change that fails this: marking the client instead of the dispatching thread. */
    @Test
    @Suppress("DEPRECATION")
    fun closeFromOutsideACallbackStillSucceeds() {
        val engine = FakeEngine()
        val client = clientOf(engine)
        val delivered = CountDownLatch(1)
        client.addObserver { delivered.countDown() }

        runBlocking { client.get(URL).close() }
        assertTrue("the observer never ran", delivered.await(10, TimeUnit.SECONDS))
        client.close()

        assertEquals(listOf("shutdown"), engine.log)
        assertThrows(IllegalStateException::class.java) { runBlocking { client.send(getRequest()) } }
    }

    /** Production change that fails this: tearing the observation scope down on the refused path. */
    @Test
    @Suppress("DEPRECATION")
    fun pendingEventsSurviveARefusedClose() {
        val client = clientOf(FakeEngine())
        val proceed = CountDownLatch(1)
        val delivered = CountDownLatch(2)
        val attempts = AtomicInteger()
        val thrown = AtomicReference<Throwable?>()
        client.addObserver {
            // Holds the collector until both events are buffered, so the second one is pending
            // when the refused close lands.
            proceed.await(10, TimeUnit.SECONDS)
            if (attempts.getAndIncrement() == 0) thrown.set(runCatching { client.close() }.exceptionOrNull())
            delivered.countDown()
        }

        runBlocking {
            client.get(URL).close()
            client.get(URL).close()
        }
        proceed.countDown()

        assertTrue("${delivered.count} of 2 events never arrived", delivered.await(10, TimeUnit.SECONDS))
        assertTrue("got ${thrown.get()}", thrown.get() is IllegalStateException)
        client.close()
    }

    /**
     * Production change that fails this: pointing the pipeline at an Observation other than the one
     * backing [ApifierClient.events], which the deprecated observer path would not notice.
     */
    @Test
    fun eventsCarriesTerminalEventsForCallsMadeThroughTheClient() {
        val client = clientOf(FakeEngine())
        val seen = AtomicReference<RequestEvent>()
        val delivered = CountDownLatch(1)

        runBlocking {
            // UNDISPATCHED so the collector is subscribed before the call runs; events replays
            // nothing, so an emission before the first subscriber is dropped.
            val collector = launch(Dispatchers.IO, CoroutineStart.UNDISPATCHED) {
                client.events.collect {
                    seen.set(it)
                    delivered.countDown()
                }
            }

            client.get(URL).close()

            assertTrue(delivered.await(5, TimeUnit.SECONDS))
            collector.cancel()
        }

        assertEquals(Outcome.SUCCESS, seen.get().outcome)
        client.close()
    }

    @Test
    @Suppress("DEPRECATION")
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
    @Suppress("DEPRECATION")
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
     * it fails when close stops cancelling the call it found in flight.
     */
    @Test
    @Suppress("DEPRECATION")
    fun liveEngineShutdownEndsWithoutThrowingOrHanging() {
        val provider = Class.forName("org.chromium.net.impl.JavaCronetProvider")
            .getConstructor(Context::class.java)
            .newInstance(context) as CronetProvider
        val cronet = provider.createBuilder().build()
        val engine = CronetClientEngine(cronet, emptyMap(), READ_TIMEOUT_MS)
        val server = ServerSocket(0)
        val accepted = CountDownLatch(1)
        thread(isDaemon = true) { runCatching { server.accept() }.onSuccess { accepted.countDown() } }
        val client = ApifierClient(context, NetworkConfig(), engine)

        val done = CountDownLatch(1)
        client.get("https://127.0.0.1:${server.localPort}/", countingCallback(done))
        assertTrue("the server never accepted a connection", accepted.await(10, TimeUnit.SECONDS))

        client.close()
        server.close()

        assertTrue("the cancelled call never reported back", done.await(5, TimeUnit.SECONDS))
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

    /** Fails if a transport failure reaches `onFailure` as a bare `IOException` instead of `asDeclaredFailure`'s wrap. */
    @Test
    @Suppress("DEPRECATION")
    fun enqueueFailureStillArrivesAsApifierException() {
        val engine = FakeEngine(newCallThrows = IOException("transport refused"))
        val client = clientOf(engine)
        val delivered = AtomicReference<IOException?>()
        val done = CountDownLatch(1)

        client.get(
            URL,
            object : Callback {
                override fun onResponse(call: Call, response: Response) {
                    response.close()
                    done.countDown()
                }

                override fun onFailure(call: Call, e: IOException) {
                    delivered.set(e)
                    done.countDown()
                }
            }
        )

        assertTrue(done.await(10, TimeUnit.SECONDS))
        client.close()
        assertTrue("got ${delivered.get()}", delivered.get() is ApifierException)
    }

    /** Fails if `Call.cancel()` stops tracking the launched job, e.g. by no longer reaching `PipelineCall.cancel()`. */
    @Test
    @Suppress("DEPRECATION")
    fun deprecatedCancelStillCancelsTheRequest() {
        val engine = FakeEngine(hang = true)
        val client = clientOf(engine)
        val outcome = AtomicReference<Throwable?>()
        val done = CountDownLatch(1)
        val call = client.call(getRequest())

        call.enqueue(object : Callback {
            override fun onResponse(call: Call, response: Response) {
                response.close()
                done.countDown()
            }

            override fun onFailure(call: Call, e: IOException) {
                outcome.set(e)
                done.countDown()
            }
        })
        assertTrue(engine.started.await(10, TimeUnit.SECONDS))

        call.cancel()

        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertEquals(listOf("cancel"), engine.log)
        assertTrue("got ${outcome.get()}", outcome.get() is ApifierException.Cancelled)
        client.close()
    }

    /** Fails if a callback is ever delivered inline from the transport's own thread instead of the client's dispatcher. */
    @Test
    @Suppress("DEPRECATION")
    fun callbacksDoNotRunOnTheNetworkThread() {
        val networkThread = AtomicReference<Thread?>()
        val callbackThread = AtomicReference<Thread?>()
        val engine = FakeEngine(respond = { networkThread.set(Thread.currentThread()); response(it) })
        val client = clientOf(engine)
        val done = CountDownLatch(1)

        client.get(
            URL,
            object : Callback {
                override fun onResponse(call: Call, response: Response) {
                    callbackThread.set(Thread.currentThread())
                    response.close()
                    done.countDown()
                }

                override fun onFailure(call: Call, e: IOException) = done.countDown()
            }
        )

        assertTrue(done.await(10, TimeUnit.SECONDS))
        client.close()
        assertTrue("network thread was never recorded", networkThread.get() != null)
        assertTrue("callback thread was never recorded", callbackThread.get() != null)
        assertTrue("callback ran on the network thread", networkThread.get() !== callbackThread.get())
    }

    @Test
    @Suppress("DEPRECATION")
    fun nonIoTransportFailureSurfacesAsApifierExceptionOnBothPaths() {
        val engine = FakeEngine(newCallThrows = IllegalStateException("engine went sideways"))
        val client = clientOf(engine)

        val thrown = assertThrows(ApifierException.Unexpected::class.java) {
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

    @Test
    fun sendIsSafeToCallFromTheMainDispatcher() {
        val storage = GatedCookieStorage()
        val client = clientOf(FakeEngine(), NetworkConfig(cookieStorage = storage))
        val dispatcher = singleThreadDispatcher()
        val scope = CoroutineScope(dispatcher)
        val sent = CountDownLatch(1)

        scope.launch {
            client.get(URL).close()
            sent.countDown()
        }
        assertTrue("the cookie read was never reached", storage.entered.await(10, TimeUnit.SECONDS))
        val marker = CountDownLatch(1)
        scope.launch { marker.countDown() }

        assertTrue(
            "the cookie read parked the calling dispatcher",
            marker.await(10, TimeUnit.SECONDS)
        )
        storage.release()
        assertTrue(sent.await(10, TimeUnit.SECONDS))
        dispatcher.close()
        client.close()
    }

    @Test
    fun cancellingTheCallerCancelsTheRequest() {
        val engine = FakeEngine(hang = true)
        val client = clientOf(engine)
        val outcome = AtomicReference<Throwable?>()
        val done = CountDownLatch(1)
        val job = CoroutineScope(Dispatchers.IO).launch {
            try {
                client.send(getRequest()).close()
            } catch (e: Throwable) {
                outcome.set(e)
            } finally {
                done.countDown()
            }
        }
        assertTrue(engine.started.await(10, TimeUnit.SECONDS))

        job.cancel()

        assertTrue(done.await(10, TimeUnit.SECONDS))
        assertTrue("got ${outcome.get()}", outcome.get() is CancellationException)
        assertEquals(listOf("cancel"), engine.log)
        client.close()
    }

    @Test
    fun closeCancelsInFlightSuspendCalls() {
        val engine = FakeEngine(hang = true)
        val client = clientOf(engine)
        val outcome = AtomicReference<Throwable?>()
        val done = CountDownLatch(1)
        CoroutineScope(Dispatchers.IO).launch {
            try {
                client.send(getRequest()).close()
            } catch (e: Throwable) {
                outcome.set(e)
            } finally {
                done.countDown()
            }
        }
        assertTrue(engine.started.await(10, TimeUnit.SECONDS))

        client.close()

        assertTrue("the suspended call was never reached", done.await(10, TimeUnit.SECONDS))
        assertTrue("got ${outcome.get()}", outcome.get() is ApifierException.Cancelled)
        assertEquals(listOf("cancel", "shutdown"), engine.log)
    }

    @Test
    fun closeCancelsACallStillStreamingItsBody() {
        val engine = FakeEngine()
        val client = clientOf(engine)
        val response = runBlocking { client.send(getRequest()) }
        // The drain outlasts the body, so the body has to end for close to return; it ends once
        // close has had its chance to reach the call.
        val closer = thread(isDaemon = true) {
            val deadline = System.currentTimeMillis() + 10_000
            while ("cancel" !in engine.log && System.currentTimeMillis() < deadline) {
                Thread.sleep(5)
            }
            response.close()
        }

        client.close()
        closer.join(10_000)

        assertEquals(listOf("cancel", "shutdown"), engine.log)
    }

    @Test
    fun facadeHelpersBuildEquivalentRequests() {
        val engine = FakeEngine()
        val client = clientOf(engine)
        val file = temporaryFolder.newFile("payload.bin").apply { writeBytes(ByteArray(4)) }
        val progress = MutableSharedFlow<Progress>(extraBufferCapacity = 8)

        runBlocking {
            client.get(URL).close()
            client.post(URL, "{}").close()
            client.delete(URL).close()
            client.head(URL).close()
            client.progress(progress).download(URL).close()
            client.progress(progress).upload(URL, listOf(file), listOf("field")).close()
        }
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
    fun sendAfterCloseFails() {
        val client = clientOf(FakeEngine())
        client.close()

        assertThrows(IllegalStateException::class.java) {
            runBlocking { client.send(getRequest()) }
        }
    }

    @Test
    fun derivedViewOverridesOnlyWhatItSets() {
        val retrying = FakeEngine(respond = { serverError(it) })
        val client = clientOf(retrying)

        val response = runBlocking { client.maxAttempts(3).get(URL) }
        response.close()
        assertEquals(3, retrying.seen.size)
        client.close()

        val hanging = FakeEngine(hang = true)
        val timingOut = clientOf(hanging, NetworkConfig(timeouts = TimeoutConfig(call = 200.milliseconds)))

        val thrown = assertThrows(ApifierException.CallTimeout::class.java) {
            runBlocking { timingOut.maxAttempts(3).get(URL) }
        }

        assertEquals("the client's own call timeout was discarded", 200L, thrown.timeoutMillis)
        timingOut.close()
    }

    @Test
    fun derivedViewDoesNotAffectTheParent() {
        val engine = FakeEngine(respond = { serverError(it) })
        val client = clientOf(engine)

        client.maxAttempts(3)
        runBlocking { client.get(URL).close() }

        assertEquals(1, engine.seen.size)
        client.close()
    }

    @Test
    fun derivedViewsChainCumulatively() {
        val engine = FakeEngine(respond = { serverError(it) })
        // A call timeout no derived view could survive, so an attempt ceiling that arrives
        // without the timeout beside it ends the call instead of retrying.
        val client = clientOf(engine, NetworkConfig(timeouts = TimeoutConfig(call = 1.milliseconds)))

        val response = runBlocking { client.maxAttempts(3).timeout(20.seconds).get(URL) }

        assertEquals(500, response.code)
        assertEquals(3, engine.seen.size)
        response.close()
        client.close()
    }

    @Test
    fun derivedViewSharesTheParentEngineAndJar() {
        val engine = FakeEngine()
        val storage = GatedCookieStorage().apply { release() }
        val client = clientOf(engine, NetworkConfig(cookieStorage = storage))

        runBlocking { client.maxAttempts(1).get(URL).close() }

        assertEquals("the call never reached the client's engine", 1, engine.seen.size)
        assertTrue("the client's cookie jar was bypassed", storage.reads.get() > 0)
        client.close()
    }

    @Test
    fun clearCookiesOnTheClientDropsSessionCookies() {
        val engine = FakeEngine(respond = { request ->
            response(request, headers = Headers.headersOf("Set-Cookie", "sid=abc"))
        })
        val client = clientOf(engine, NetworkConfig(cookieStorage = InMemoryCookieStorage()))

        runBlocking { client.get(URL).close() }
        client.clearCookies()
        runBlocking { client.get(URL).close() }

        val requestAfterClear = engine.seen.last()
        assertNull("the session cookie held in memory should have been cleared", requestAfterClear.header("Cookie"))
        client.close()
    }

    @Test
    fun javaTimeoutOverloadMatchesTheDurationForm() {
        val client = clientOf(FakeEngine(hang = true))

        val fromUnit = assertThrows(ApifierException.CallTimeout::class.java) {
            runBlocking { client.timeout(500, TimeUnit.MILLISECONDS).get(URL) }
        }
        val fromDuration = assertThrows(ApifierException.CallTimeout::class.java) {
            runBlocking { client.timeout(500.milliseconds).get(URL) }
        }

        assertEquals(fromDuration.timeoutMillis, fromUnit.timeoutMillis)
        assertEquals(500L, fromUnit.timeoutMillis)
        client.close()
    }

    /** Fails if the accessor that publishes the verdict is gated on the enforcement flag. */
    @Test
    fun qualificationRunsWithoutEnforcementOptIn() {
        val probes = Executors.newCachedThreadPool()
        // Every junk label answers, so the verdict can only be UNTRUSTED, and only a run that
        // happened can produce it.
        val client = ApifierClient(
            context,
            NetworkConfig(ensureTrustworthyResolver = false),
            FakeEngine(),
            qualification = qualificationOn(probes) { listOf(PUBLIC_ADDRESS) }
        )

        assertFalse(runBlocking { client.isResolverTrustworthy() })
        client.close()
        probes.shutdownNow()
    }

    /** Fails if construction awaits the first verdict. */
    @Test
    fun constructionDoesNotWaitForTheGlobalVerdict() {
        val constructed = CountDownLatch(1)
        val built = AtomicReference<ApifierClient?>()

        thread(isDaemon = true) {
            built.set(ApifierClient(context, NetworkConfig(), FakeEngine(), qualification = pendingQualification()))
            constructed.countDown()
        }

        assertTrue("construction never returned", constructed.await(10, TimeUnit.SECONDS))
        built.get()?.close()
    }

    /** Fails if the accessor answers from a default instead of suspending until a verdict lands. */
    @Test
    fun isResolverTrustworthyAwaitsTheFirstVerdict() {
        val answer = CountDownLatch(1)
        val probes = Executors.newCachedThreadPool()
        val client = ApifierClient(
            context,
            NetworkConfig(),
            FakeEngine(),
            qualification = qualificationOn(probes) { host ->
                answer.await(10, TimeUnit.SECONDS)
                if (host.endsWith(INVALID_SUFFIX)) emptyList() else listOf(PUBLIC_ADDRESS)
            }
        )
        val trustworthy = AtomicBoolean(false)
        val returned = CountDownLatch(1)
        CoroutineScope(Dispatchers.IO).launch {
            trustworthy.set(client.isResolverTrustworthy())
            returned.countDown()
        }

        assertFalse("the accessor answered before any verdict", returned.await(300, TimeUnit.MILLISECONDS))
        answer.countDown()

        assertTrue("the accessor never returned", returned.await(10, TimeUnit.SECONDS))
        assertTrue(trustworthy.get())
        client.close()
        probes.shutdownNow()
    }

    /** Fails if the network callback stops flushing the verdicts, or is registered only when enforcing. */
    @Test
    fun aNetworkChangeFlushesTheClientVerdicts() {
        val rounds = AtomicInteger()
        val client = ApifierClient(
            context,
            NetworkConfig(),
            FakeEngine(),
            // Clean on the first round only, so a verdict computed after the flush differs.
            qualification = qualificationOn(Executor { it.run() }) { host ->
                if (rounds.get() == 0 && host.endsWith(INVALID_SUFFIX)) emptyList() else listOf(PUBLIC_ADDRESS)
            }
        )
        assertTrue(runBlocking { client.isResolverTrustworthy() })

        rounds.incrementAndGet()
        val manager = shadowOf(context.getSystemService(ConnectivityManager::class.java))
        manager.networkCallbacks.forEach { it.onAvailable(ShadowNetwork.newInstance(1)) }

        assertFalse(runBlocking { client.isResolverTrustworthy() })
        client.close()
    }

    private fun getRequest(): Request = Request.Builder().url(URL).get().build()

    private fun singleThreadDispatcher(): ExecutorCoroutineDispatcher =
        Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "main-like").apply { isDaemon = true }
        }.asCoroutineDispatcher()

    /** Stands in for a [CookieStorage] whose reads reach a disk or a keystore. */
    private class GatedCookieStorage : CookieStorage {

        val entered = CountDownLatch(1)
        val reads = AtomicInteger()

        private val proceed = CountDownLatch(1)
        private val delegate = InMemoryCookieStorage()

        fun release() = proceed.countDown()

        override fun getStringSet(key: String, defaultValue: Set<String>?): Set<String>? {
            reads.incrementAndGet()
            entered.countDown()
            proceed.await(10, TimeUnit.SECONDS)
            return delegate.getStringSet(key, defaultValue)
        }

        override fun putStringSet(key: String, value: Set<String>) = delegate.putStringSet(key, value)

        override fun remove(key: String) = delegate.remove(key)
    }

    private fun clientOf(engine: FakeEngine, config: NetworkConfig = NetworkConfig()) =
        ApifierClient(context, config, engine, qualification = qualificationOn(Executor { it.run() }, CLEAN_RESOLVE))

    private fun qualificationOn(executor: Executor, resolve: (String) -> List<String>) = ResolverQualification(
        resolve = resolve,
        executor = executor,
        junkLabelCount = 1,
        canaries = listOf(CANARY),
        clock = System::currentTimeMillis
    )

    /** No verdict ever arrives: the probe executor drops the work it is handed. */
    private fun pendingQualification() = qualificationOn(Executor { }) { emptyList() }

    @Suppress("DEPRECATION")
    private fun countingCallback(latch: CountDownLatch) = object : Callback {
        override fun onResponse(call: Call, response: Response) {
            response.close()
            latch.countDown()
        }

        override fun onFailure(call: Call, e: IOException) = latch.countDown()
    }

    private fun serverError(request: Request): Response = response(request, 500)

    private fun response(
        request: Request,
        code: Int = 200,
        headers: Headers = Headers.headersOf()
    ): Response = Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_2)
        .code(code)
        .message("")
        .headers(headers)
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

            override suspend fun await(): Response = suspendCancellableCoroutine { continuation ->
                continuation.invokeOnCancellation { cancel() }
                thread(isDaemon = true) {
                    started.countDown()
                    if (hang) cancelSignal.await(30, TimeUnit.SECONDS)
                    if (canceled.get()) {
                        deliver { continuation.resumeWithException(ApifierException.Cancelled()) }
                    } else {
                        listener?.onResponseStarted(0, request.uri)
                        deliver {
                            continuation.resume(respond(request)) { _, undelivered, _ -> undelivered.close() }
                        }
                    }
                    listener?.onTransferComplete(0, 0)
                }
            }

            override fun cancel() {
                if (!canceled.compareAndSet(false, true)) return
                record("cancel")
                cancelSignal.countDown()
            }

            private fun deliver(outcome: () -> Unit) {
                if (delivered.compareAndSet(false, true)) outcome()
            }
        }
    }

    private companion object {
        const val URL = "https://api.example.com/resource"
        const val CANARY = "canary.example.org"
        const val INVALID_SUFFIX = ".invalid"
        const val PUBLIC_ADDRESS = "93.184.216.34"
        val CLEAN_RESOLVE: (String) -> List<String> = { host ->
            if (host.endsWith(INVALID_SUFFIX)) emptyList() else listOf(PUBLIC_ADDRESS)
        }
        const val READ_TIMEOUT_MS = 5_000L
    }
}
