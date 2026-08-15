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
package com.androidacy.apifier.observe

import com.androidacy.apifier.client.AttemptCall
import com.androidacy.apifier.client.BreakerRegistry
import com.androidacy.apifier.client.CallOptions
import com.androidacy.apifier.client.CircuitBreakerConfig
import com.androidacy.apifier.client.NetworkConfig
import com.androidacy.apifier.client.Pipeline
import com.androidacy.apifier.client.PipelineCall
import com.androidacy.apifier.client.RetryConfig
import com.androidacy.apifier.client.TransportListener
import com.androidacy.apifier.dns.ResolverQualification
import com.androidacy.apifier.http.ApifierException
import com.androidacy.apifier.http.ErrorCode
import com.androidacy.apifier.http.Headers
import com.androidacy.apifier.http.Protocol
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.http.Response
import com.androidacy.apifier.http.ResponseBody
import com.androidacy.apifier.http.ResponseBody.Companion.toResponseBody
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.coroutines.resumeWithException

@Suppress("DEPRECATION")
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class ObservationTest {

    private val scheduler = Executors.newSingleThreadScheduledExecutor()

    @After
    fun tearDown() {
        scheduler.shutdownNow()
    }

    @Test
    fun globalObserverSeesEveryAttemptWithWillRetry() {
        val transport = FakeTransport(listOf(step { ok(it, 500) }, step { ok(it) }))
        val observation = Observation()
        val events = recordingObserver()
        observation.addObserver(events.first)
        val pipeline = pipelineOf(transport, config(retry = RetryConfig(maxAttempts = 2)), observation)

        pipeline.executeBlocking(request(), CallOptions(), PipelineCall()).close()
        val seen = awaitEvents(events.second, 2)

        assertEquals(listOf(1, 2), seen.map { it.attempt })
        assertEquals(listOf(true, false), seen.map { it.willRetry })
        assertEquals(listOf(500, 200), seen.map { it.responseCode })
    }

    @Test
    fun perRequestObserverSeesExactlyOneTerminalEvent() {
        val transport = FakeTransport(listOf(step { ok(it, 500) }, step { ok(it) }))
        val observation = Observation()
        val pipeline = pipelineOf(transport, config(retry = RetryConfig(maxAttempts = 2)), observation)
        val perRequest = recordingObserver()

        pipeline.executeBlocking(request(), CallOptions(observer = perRequest.first), PipelineCall()).close()
        val seen = awaitEvents(perRequest.second, 1)

        assertEquals(1, seen.size)
        assertEquals(200, seen[0].responseCode)
        assertFalse(seen[0].willRetry)
    }

    @Test
    fun exhaustedRetriesDeliverLastFailurePerRequest() {
        val transport = FakeTransport(
            listOf(step { throw transportFailure(ErrorCode.CONNECTION_RESET) }, step { throw transportFailure(ErrorCode.TIMED_OUT) })
        )
        val observation = Observation()
        val pipeline = pipelineOf(transport, config(retry = RetryConfig(maxAttempts = 2)), observation)
        val perRequest = recordingObserver()

        runCatching {
            pipeline.executeBlocking(request(), CallOptions(observer = perRequest.first), PipelineCall())
        }
        val seen = awaitEvents(perRequest.second, 1)

        assertEquals(1, seen.size)
        assertEquals(ErrorCode.TIMED_OUT, seen[0].errorCode)
        assertEquals(Outcome.FAILED, seen[0].outcome)
    }

    @Test
    fun failureEventCarriesErrorCodeNullResponseCode() {
        val transport = FakeTransport(listOf(step { throw transportFailure(ErrorCode.CONNECTION_RESET) }))
        val observation = Observation()
        val events = recordingObserver()
        observation.addObserver(events.first)
        val pipeline = pipelineOf(transport, config(), observation)

        runCatching { pipeline.executeBlocking(request(), CallOptions(), PipelineCall()) }
        val seen = awaitEvents(events.second, 1)

        assertEquals(Outcome.FAILED, seen[0].outcome)
        assertEquals(ErrorCode.CONNECTION_RESET, seen[0].errorCode)
        assertNull(seen[0].responseCode)
    }

    @Test
    fun emitDoesNotBlockOnSlowObserver() {
        val observation = Observation()
        val started = CountDownLatch(1)
        observation.addObserver {
            started.countDown()
            Thread.sleep(5_000)
        }

        val elapsedMs = measureMillis { observation.emit(sampleEvent(), null) }
        assertTrue("emit() took ${elapsedMs}ms", elapsedMs < 500)
        assertTrue(started.await(1, TimeUnit.SECONDS))
    }

    @Test
    fun throwingObserverIsolated() {
        val observation = Observation()
        val secondSeen = CountDownLatch(1)
        observation.addObserver { throw IllegalStateException("boom") }
        observation.addObserver { secondSeen.countDown() }

        observation.emit(sampleEvent(), null)

        assertTrue(secondSeen.await(2, TimeUnit.SECONDS))
    }

    @Test
    fun closeDrainsPendingEvents() {
        val observation = Observation()
        val delivered = AtomicInteger(0)
        observation.addObserver { delivered.incrementAndGet() }

        repeat(20) { observation.emit(sampleEvent(), null) }
        observation.close()

        assertEquals(20, delivered.get())
    }

    /**
     * Production change that fails this: counting a delivery as pending at emit() time and only
     * clearing it when the compat collector actually processes the event. A slow observer stalls
     * that collector; DROP_OLDEST then evicts events that were never handed to it, so their count
     * never clears, and close() burns the full close timeout waiting for a number that can't reach zero.
     */
    @Test
    fun closeDoesNotStrandCountOnEventsDroppedByASlowObserver() {
        val observation = Observation()
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        observation.addObserver {
            started.countDown()
            release.await(5, TimeUnit.SECONDS)
        }

        observation.emit(sampleEvent(), null)
        assertTrue(started.await(2, TimeUnit.SECONDS))
        repeat(EVENT_BUFFER_CAPACITY + 50) { observation.emit(sampleEvent(), null) }
        release.countDown()

        val elapsedMs = measureMillis { observation.close() }
        assertTrue("close() took ${elapsedMs}ms", elapsedMs < 1_000)
    }

    /** Production change that fails this: letting the closed-state check in emit() fall through. */
    @Test
    fun eventsAfterCloseAreDroppedNotThrown() {
        val observation = Observation()
        val seen = recordingObserver()
        observation.addObserver(seen.first)
        observation.close()

        observation.emit(sampleEvent(), null)

        Thread.sleep(50)
        assertTrue(seen.second.isEmpty())
    }

    /** Production change that fails this: subscribing the compatibility collector asynchronously. */
    @Test
    fun eventEmittedBeforeFirstCollectIsNotLost() {
        val observation = Observation()
        val delivered = CountDownLatch(1)
        observation.addObserver { delivered.countDown() }

        observation.emit(sampleEvent(), null)

        assertTrue(delivered.await(2, TimeUnit.SECONDS))
        observation.close()
    }

    /** Production change that fails this: collecting the compatibility flow with Dispatchers.Unconfined. */
    @Test
    fun observerRunsOffTheEmittingThread() {
        val observation = Observation()
        val callbackThread = AtomicReference<Thread>()
        val delivered = CountDownLatch(1)
        observation.addObserver {
            callbackThread.set(Thread.currentThread())
            delivered.countDown()
        }

        observation.emit(sampleEvent(), null)

        assertTrue(delivered.await(2, TimeUnit.SECONDS))
        assertNotEquals(Thread.currentThread(), callbackThread.get())
        observation.close()
    }

    /**
     * Production change that fails this: changing onBufferOverflow to SUSPEND. Under SUSPEND,
     * `tryEmit` fails fast instead of dropping the oldest buffered value once a permanently stuck
     * collector fills the buffer, so the flood's newest event would never reach a subscriber.
     */
    @Test
    fun slowCollectorDropsOldestInsteadOfBlocking() = runTest {
        val observation = Observation()
        val release = CompletableDeferred<Unit>()
        val collected = mutableListOf<RequestEvent>()
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        scope.launch {
            observation.events.collect { event ->
                if (collected.isEmpty()) release.await()
                collected.add(event)
            }
        }

        val total = EVENT_BUFFER_CAPACITY + 100
        val elapsedMs = measureMillis {
            repeat(total) { i -> observation.emit(sampleEvent(attempt = i), null) }
        }
        assertTrue("emit loop took ${elapsedMs}ms", elapsedMs < 2_000)

        release.complete(Unit)

        assertTrue("nothing dropped: ${collected.size} of $total collected", collected.size < total)
        assertEquals(total - 1, collected.last().attempt)
        scope.cancel()
        observation.close()
    }

    @Test
    fun bytesAndTtfbFlowFromTransport() {
        val transport = FakeTransport(listOf(step(ttfbMillis = 42, bytesSent = 7, bytesReceived = 99) { ok(it) }))
        val observation = Observation()
        val events = recordingObserver()
        observation.addObserver(events.first)
        val pipeline = pipelineOf(transport, config(), observation)

        pipeline.executeBlocking(request(), CallOptions(), PipelineCall()).close()
        val seen = awaitEvents(events.second, 1)

        assertEquals(42L, seen[0].ttfbMillis)
        assertEquals(7L, seen[0].bytesSent)
        assertEquals(99L, seen[0].bytesReceived)
    }

    /**
     * Production change that fails this: the fake delivering the response before signalling
     * transfer completion, the ordering the real transport does not have, would let this pass
     * even if the pipeline read [ErrorCode] before it was final.
     */
    @Test
    fun bytesReceivedWaitsForTransferCompleteNotHeaders() {
        val gate = CountDownLatch(1)
        val transport = FakeTransport(listOf(step(bytesReceived = 500, transferGate = gate) { ok(it) }))
        val observation = Observation()
        val events = recordingObserver()
        observation.addObserver(events.first)
        val pipeline = pipelineOf(transport, config(), observation)

        pipeline.executeBlocking(request(), CallOptions(), PipelineCall()).close()
        assertTrue("event delivered before the transport signalled completion", events.second.isEmpty())

        gate.countDown()
        val seen = awaitEvents(events.second, 1)

        assertEquals(500L, seen[0].bytesReceived)
    }

    /** Production change that fails this: throwing from the trust gate or breaker without going through the execute() catch-all. */
    @Test
    fun circuitOpenReachesPerRequestObserverAndCountsAsAnAttempt() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val observation = Observation()
        val breakers = BreakerRegistry(CircuitBreakerConfig(failureThreshold = 1))
        breakers.forHost(HOST)?.recordFailure()
        val pipeline = pipelineOf(transport, config(), observation, breakers = breakers)
        val perRequest = recordingObserver()

        val thrown = runCatching {
            pipeline.executeBlocking(request(), CallOptions(observer = perRequest.first), PipelineCall())
        }.exceptionOrNull()
        val seen = awaitEvents(perRequest.second, 1)

        assertTrue(thrown is ApifierException.CircuitOpen)
        assertEquals(1, seen.size)
        assertEquals(ErrorCode.CIRCUIT_OPEN, seen[0].errorCode)
        assertEquals(Outcome.FAILED, seen[0].outcome)
        assertNull(seen[0].responseCode)
        assertFalse(seen[0].willRetry)
        assertEquals(0, transport.seenCount)
    }

    /** Production change that fails this: dropping the builder-level default observer fallback on the terminal-failure path. */
    @Test
    fun circuitOpenReachesTheBuilderDefaultObserverWhenNoCallSetsOne() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val observation = Observation()
        val breakers = BreakerRegistry(CircuitBreakerConfig(failureThreshold = 1))
        breakers.forHost(HOST)?.recordFailure()
        val default = recordingObserver()
        val pipeline = pipelineOf(transport, config().copy(defaultObserver = default.first), observation, breakers = breakers)

        val thrown = runCatching {
            pipeline.executeBlocking(request(), CallOptions(), PipelineCall())
        }.exceptionOrNull()
        val seen = awaitEvents(default.second, 1)

        assertTrue(thrown is ApifierException.CircuitOpen)
        assertEquals(1, seen.size)
        assertEquals(ErrorCode.CIRCUIT_OPEN, seen[0].errorCode)
        assertEquals(0, transport.seenCount)
    }

    /** Production change that fails this: the trust gate's throw never reaching execute()'s catch-all. */
    @Test
    fun dnsUntrustedReachesPerRequestObserver() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val observation = Observation()
        val pipeline = pipelineOf(
            transport,
            config(enforceResolver = true),
            observation,
            // An answer for a name that is never delegated, which is a resolver rewriting NXDOMAIN.
            qualification = qualification { listOf(PUBLIC_ADDRESS) }
        )
        val perRequest = recordingObserver()

        val thrown = runCatching {
            pipeline.executeBlocking(request(), CallOptions(observer = perRequest.first), PipelineCall())
        }.exceptionOrNull()
        val seen = awaitEvents(perRequest.second, 1)

        assertTrue(thrown is ApifierException.DnsUntrusted)
        assertEquals(1, seen.size)
        assertEquals(ErrorCode.DNS_UNTRUSTED, seen[0].errorCode)
        assertEquals(0, transport.seenCount)
    }

    /**
     * Production change that fails this: reintroducing the backoffSleep-inside-the-attempt-try/catch
     * bug, which either drops this terminal event or double-reports it to the global observer under
     * the just-completed attempt's number.
     */
    @Test
    fun cancelDuringBackoffReachesPerRequestWithoutDoublingGlobal() {
        val transport = FakeTransport(listOf(step(ttfbMillis = 10, bytesReceived = 123) { ok(it, 500) }, step { ok(it) }))
        val observation = Observation()
        val global = recordingObserver()
        observation.addObserver(global.first)
        val pipeline = pipelineOf(transport, config(retry = RetryConfig(maxAttempts = 2)), observation)
        val perRequest = recordingObserver()
        val call = PipelineCall()
        thread(isDaemon = true) {
            Thread.sleep(150)
            call.cancel()
        }

        runCatching { pipeline.executeBlocking(request(), CallOptions(observer = perRequest.first), call) }

        val perRequestSeen = awaitEvents(perRequest.second, 1)
        val globalSeen = awaitEvents(global.second, 2)

        assertEquals(1, perRequestSeen.size)
        assertEquals(ErrorCode.CANCELLED, perRequestSeen[0].errorCode)
        assertEquals(Outcome.FAILED, perRequestSeen[0].outcome)
        assertEquals(2, globalSeen.size)
        assertEquals(listOf(500, null), globalSeen.map { it.responseCode })
        assertEquals(listOf(true, false), globalSeen.map { it.willRetry })
        // The terminal event never reached the transport, so it must carry clean zero metrics,
        // not the first attempt's already-complete ttfb/bytes reused by re-catching a cancel
        // that landed in backoff under the same try/catch that reported the first attempt.
        assertNull(globalSeen[1].ttfbMillis)
        assertEquals(0L, globalSeen[1].bytesReceived)
    }

    /**
     * Production change that fails this: reporting the timeout past the terminal-event guard, so
     * the attempt and execute's catch-all both report the same call.
     */
    @Test
    fun timeoutEmitsExactlyOneTerminalEvent() {
        val transport = FakeTransport(listOf(step(answersOnlyToCancel = true) { ok(it) }))
        val observation = Observation()
        val global = recordingObserver()
        observation.addObserver(global.first)
        val pipeline = pipelineOf(transport, config(), observation)

        val thrown = runCatching {
            pipeline.executeBlocking(request(), CallOptions(callTimeoutMillis = 200), PipelineCall())
        }.exceptionOrNull()
        awaitEvents(global.second, 1)
        // A duplicate would follow on the same emit path, so let it land before counting.
        Thread.sleep(200)

        assertTrue("got $thrown", thrown is ApifierException.CallTimeout)
        assertEquals(1, global.second.size)
        assertEquals(Outcome.FAILED, global.second[0].outcome)
        assertFalse(global.second[0].willRetry)
    }

    /**
     * Production change that fails this: reporting the attempt before deciding the surrender, which
     * ends the call with a SUCCESS event and then throws the timeout.
     */
    @Test
    fun timeoutRacingTheHandoverReportsFailureNotSuccess() {
        val call = PipelineCall()
        val transport = FakeTransport(listOf(step { call.markTimedOut(); ok(it) }))
        val observation = Observation()
        val global = recordingObserver()
        observation.addObserver(global.first)
        val pipeline = pipelineOf(transport, config(), observation)

        val thrown = runCatching { pipeline.executeBlocking(request(), CallOptions(), call) }.exceptionOrNull()
        awaitEvents(global.second, 1)
        // A duplicate would follow on the same emit path, so let it land before counting.
        Thread.sleep(200)

        assertTrue("got $thrown", thrown is ApifierException.CallTimeout)
        assertEquals("one terminal event, got ${global.second}", 1, global.second.size)
        assertEquals(Outcome.FAILED, global.second[0].outcome)
        assertEquals(ErrorCode.CALL_TIMEOUT, global.second[0].errorCode)
    }

    /** Production change that fails this: dropping the else branch that maps an unmodelled throwable. */
    @Test
    fun aThrowingDynamicHeaderProviderStillReportsATerminalEvent() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val observation = Observation()
        val provider: () -> String = { throw IllegalStateException("no nonce available") }
        val pipeline = pipelineOf(transport, config(dynamicHeaders = mapOf("X-Nonce" to provider)), observation)
        val perRequest = recordingObserver()

        val thrown = runCatching {
            pipeline.executeBlocking(request(), CallOptions(observer = perRequest.first), PipelineCall())
        }.exceptionOrNull()
        val seen = awaitEvents(perRequest.second, 1)

        assertTrue("got $thrown", thrown is IllegalStateException)
        assertEquals(1, seen.size)
        assertEquals(Outcome.FAILED, seen[0].outcome)
        assertEquals(ErrorCode.OTHER, seen[0].errorCode)
        assertEquals(0, transport.seenCount)
    }

    /** Production change that fails this: any end path that emits no terminal event, or two. */
    @Test
    fun everyEndedCallReportsExactlyOneTerminalEvent() {
        val successEvents = terminalEventsOf(FakeTransport(listOf(step { ok(it) })))
        val failureEvents = terminalEventsOf(
            FakeTransport(listOf(step { throw transportFailure(ErrorCode.CONNECTION_RESET) }))
        )
        val canceledCall = PipelineCall()
        thread(isDaemon = true) {
            Thread.sleep(150)
            canceledCall.cancel()
        }
        val cancelEvents = terminalEventsOf(
            FakeTransport(listOf(step(answersOnlyToCancel = true) { ok(it) })),
            call = canceledCall
        )
        val timeoutEvents = terminalEventsOf(
            FakeTransport(listOf(step(answersOnlyToCancel = true) { ok(it) })),
            options = CallOptions(callTimeoutMillis = 200)
        )
        // A header value the request builder refuses leaves the call with an IllegalArgumentException.
        val unmodelledEvents = terminalEventsOf(
            FakeTransport(listOf(step { ok(it) })),
            config = config(headers = mapOf("X-Trace" to "one\ntwo"))
        )

        assertEquals("success: $successEvents", 1, successEvents.size)
        assertEquals("transport failure: $failureEvents", 1, failureEvents.size)
        assertEquals("cancel: $cancelEvents", 1, cancelEvents.size)
        assertEquals("timeout: $timeoutEvents", 1, timeoutEvents.size)
        assertEquals("unmodelled throwable: $unmodelledEvents", 1, unmodelledEvents.size)
    }

    /** Runs one call to its end and returns the terminal events a global observer saw. */
    private fun terminalEventsOf(
        transport: FakeTransport,
        config: NetworkConfig = config(),
        options: CallOptions = CallOptions(),
        call: PipelineCall = PipelineCall()
    ): List<RequestEvent> {
        val observation = Observation()
        val global = recordingObserver()
        observation.addObserver(global.first)

        runCatching { pipelineOf(transport, config, observation).executeBlocking(request(), options, call).close() }
        awaitEvents(global.second, 1)
        // A duplicate would follow on the same emit path, so let it land before counting.
        Thread.sleep(200)
        observation.close()

        return global.second.filter { !it.willRetry }
    }

    private fun measureMillis(block: () -> Unit): Long {
        val start = System.nanoTime()
        block()
        return (System.nanoTime() - start) / 1_000_000
    }

    private fun recordingObserver(): Pair<RequestObserver, CopyOnWriteArrayList<RequestEvent>> {
        val seen = CopyOnWriteArrayList<RequestEvent>()
        return RequestObserver { seen.add(it) } to seen
    }

    private fun awaitEvents(seen: CopyOnWriteArrayList<RequestEvent>, count: Int): List<RequestEvent> {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (seen.size < count && System.nanoTime() < deadline) Thread.sleep(10)
        return seen.toList()
    }

    private fun sampleEvent(attempt: Int = 1) = RequestEvent(
        outcome = Outcome.SUCCESS,
        errorCode = null,
        responseCode = 200,
        elapsedMillis = 1,
        ttfbMillis = 1,
        bytesSent = 0,
        bytesReceived = 0,
        host = HOST,
        method = "GET",
        attempt = attempt,
        provider = "test",
        willRetry = false
    )

    /** Runs [Pipeline.execute] synchronously; production dropped this alongside the deprecated blocking `Call.execute`. */
    private fun Pipeline.executeBlocking(request: Request, options: CallOptions, call: PipelineCall): Response =
        runBlocking { execute(request, options, call) }

    private fun request(): Request = Request.Builder().url("https://$HOST/resource").build()

    private fun config(
        retry: RetryConfig = RetryConfig(),
        headers: Map<String, String> = emptyMap(),
        dynamicHeaders: Map<String, () -> String> = emptyMap(),
        enforceResolver: Boolean = false
    ) = NetworkConfig(
        headers = headers,
        dynamicHeaders = dynamicHeaders,
        retryConfig = retry,
        ensureTrustworthyResolver = enforceResolver
    )

    private fun pipelineOf(
        transport: FakeTransport,
        config: NetworkConfig,
        observation: Observation,
        breakers: BreakerRegistry = BreakerRegistry(config.circuitBreakerConfig),
        qualification: ResolverQualification = qualification { host ->
            if (host.endsWith(".invalid")) emptyList() else listOf(PUBLIC_ADDRESS)
        }
    ) = Pipeline(
        transport::newCall,
        config,
        null,
        null,
        qualification,
        breakers,
        scheduler,
        "test-provider",
        observation
    )

    /** Runs every probe on the calling thread, so a verdict is settled by the time a read returns. */
    private fun qualification(resolve: (String) -> List<String>) = ResolverQualification(
        resolve = resolve,
        executor = Executor { it.run() },
        junkLabelCount = 1,
        canaries = listOf("canary.example.org"),
        clock = { 0L }
    )

    private fun ok(request: Request, code: Int = 200, body: ResponseBody = ByteArray(0).toResponseBody(null)): Response =
        Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_2)
            .code(code)
            .message("")
            .headers(Headers.headersOf())
            .body(body)
            .build()

    private fun transportFailure(errorCode: ErrorCode) = ApifierException.Transport(
        errorCode = errorCode,
        cronetErrorCode = 0,
        immediatelyRetryable = true,
        message = "failure",
        cause = null
    )

    private fun step(
        ttfbMillis: Long? = null,
        bytesSent: Long = 0,
        bytesReceived: Long = 0,
        transferGate: CountDownLatch? = null,
        answersOnlyToCancel: Boolean = false,
        produce: (Request) -> Response
    ) = Step(ttfbMillis, bytesSent, bytesReceived, transferGate, answersOnlyToCancel, produce)

    private class Step(
        val ttfbMillis: Long?,
        val bytesSent: Long,
        val bytesReceived: Long,
        val transferGate: CountDownLatch?,
        /** Never answers on its own, the way a host that burns the whole call budget behaves. */
        val answersOnlyToCancel: Boolean,
        val produce: (Request) -> Response
    )

    private class FakeTransport(private val steps: List<Step>) {
        private val seen = AtomicInteger(0)

        val seenCount: Int get() = seen.get()

        fun newCall(request: Request, listener: TransportListener?): AttemptCall {
            val index = seen.getAndIncrement()
            val step = steps[minOf(index, steps.size - 1)]
            return FakeCall(request, listener, step)
        }
    }

    /**
     * Mirrors the real transport's call ordering: the response is delivered from whatever stands
     * in for "headers arrived", and the transfer-complete signal fires afterwards, optionally
     * held back by [Step.transferGate] to prove a consumer can't observe bytes early.
     */
    private class FakeCall(
        private val request: Request,
        private val listener: TransportListener?,
        private val step: Step
    ) : AttemptCall {
        private val canceled = AtomicBoolean(false)
        private val delivered = AtomicBoolean(false)
        private val cancelSignal = CountDownLatch(1)

        override suspend fun await(): Response = suspendCancellableCoroutine { continuation ->
            continuation.invokeOnCancellation { cancel() }
            thread(isDaemon = true) {
                step.ttfbMillis?.let { listener?.onResponseStarted(it, request.uri) }
                if (step.answersOnlyToCancel) {
                    cancelSignal.await(10, TimeUnit.SECONDS)
                    deliver { continuation.resumeWithException(ApifierException.Cancelled()) }
                    listener?.onTransferComplete(step.bytesSent, step.bytesReceived)
                    return@thread
                }
                try {
                    val response = step.produce(request)
                    deliver { continuation.resume(response) { _, undelivered, _ -> undelivered.close() } }
                    step.transferGate?.await(5, TimeUnit.SECONDS)
                    listener?.onTransferComplete(step.bytesSent, step.bytesReceived)
                } catch (e: IOException) {
                    deliver { continuation.resumeWithException(e) }
                    listener?.onTransferComplete(step.bytesSent, step.bytesReceived)
                }
            }
        }

        override fun cancel() {
            canceled.set(true)
            cancelSignal.countDown()
        }

        private fun deliver(outcome: () -> Unit) {
            if (delivered.compareAndSet(false, true)) outcome()
        }
    }

    private companion object {
        const val HOST = "api.example.com"
        const val PUBLIC_ADDRESS = "93.184.216.34"

        /** Mirrors Observation's own extraBufferCapacity, so the flood test can size past it. */
        const val EVENT_BUFFER_CAPACITY = 1024
    }
}
