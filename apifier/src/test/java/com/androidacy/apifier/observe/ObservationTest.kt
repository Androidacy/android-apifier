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

import com.androidacy.apifier.client.BreakerRegistry
import com.androidacy.apifier.client.CallOptions
import com.androidacy.apifier.client.CircuitBreakerConfig
import com.androidacy.apifier.client.NetworkConfig
import com.androidacy.apifier.client.Pipeline
import com.androidacy.apifier.client.PipelineCall
import com.androidacy.apifier.client.RetryConfig
import com.androidacy.apifier.client.TransportListener
import com.androidacy.apifier.dns.DnsAnswer
import com.androidacy.apifier.dns.PinnedRootTrust
import com.androidacy.apifier.dns.ProtectedDomainCheck
import com.androidacy.apifier.dns.TrustedResolver
import com.androidacy.apifier.http.ApifierException
import com.androidacy.apifier.http.Call
import com.androidacy.apifier.http.Callback
import com.androidacy.apifier.http.ErrorCode
import com.androidacy.apifier.http.Headers
import com.androidacy.apifier.http.Protocol
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.http.Response
import com.androidacy.apifier.http.ResponseBody
import com.androidacy.apifier.http.ResponseBody.Companion.toResponseBody
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

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

        pipeline.execute(request(), CallOptions(), PipelineCall()).close()
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

        pipeline.execute(request(), CallOptions(observer = perRequest.first), PipelineCall()).close()
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
            pipeline.execute(request(), CallOptions(observer = perRequest.first), PipelineCall())
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

        runCatching { pipeline.execute(request(), CallOptions(), PipelineCall()) }
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

    /** Production change that fails this: dropping the RejectedExecutionException catch in emit(). */
    @Test
    fun emitAfterCloseDoesNotThrow() {
        // AbortPolicy, the default RejectedExecutionHandler, throws RejectedExecutionException on
        // a post-shutdown submission; DiscardOldestPolicy (Observation's own default) swallows it
        // silently instead, which would mask a missing catch in emit() if used here.
        val executor = ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, LinkedBlockingQueue())
        val observation = Observation(executor)
        observation.close()

        observation.emit(sampleEvent(), null)
    }

    @Test
    fun bytesAndTtfbFlowFromTransport() {
        val transport = FakeTransport(listOf(step(ttfbMillis = 42, bytesSent = 7, bytesReceived = 99) { ok(it) }))
        val observation = Observation()
        val events = recordingObserver()
        observation.addObserver(events.first)
        val pipeline = pipelineOf(transport, config(), observation)

        pipeline.execute(request(), CallOptions(), PipelineCall()).close()
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

        pipeline.execute(request(), CallOptions(), PipelineCall()).close()
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
            pipeline.execute(request(), CallOptions(observer = perRequest.first), PipelineCall())
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

    /** Production change that fails this: the trust gate's throw never reaching execute()'s catch-all. */
    @Test
    fun dnsUntrustedReachesPerRequestObserver() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val observation = Observation()
        val pipeline = pipelineOf(transport, config(), observation, trustCheck = failingTrustCheck())
        val perRequest = recordingObserver()

        val thrown = runCatching {
            pipeline.execute(request(), CallOptions(observer = perRequest.first), PipelineCall())
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

        runCatching { pipeline.execute(request(), CallOptions(observer = perRequest.first), call) }

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

    private fun sampleEvent() = RequestEvent(
        outcome = Outcome.SUCCESS,
        errorCode = null,
        responseCode = 200,
        elapsedMillis = 1,
        ttfbMillis = 1,
        bytesSent = 0,
        bytesReceived = 0,
        host = HOST,
        method = "GET",
        attempt = 1,
        provider = "test",
        willRetry = false
    )

    private fun request(): Request = Request.Builder().url("https://$HOST/resource").build()

    private fun config(retry: RetryConfig = RetryConfig()) = NetworkConfig(retryConfig = retry)

    private fun pipelineOf(
        transport: FakeTransport,
        config: NetworkConfig,
        observation: Observation,
        breakers: BreakerRegistry = BreakerRegistry(config.circuitBreakerConfig),
        trustCheck: ProtectedDomainCheck? = null
    ) = Pipeline(
        transport::newCall,
        config,
        null,
        null,
        trustCheck,
        breakers,
        scheduler,
        "test-provider",
        observation
    )

    /** A verdict of FAIL: every trusted resolver disagrees with what the system resolver answered. */
    private fun failingTrustCheck(): ProtectedDomainCheck {
        val store = KeyStore.getInstance("PKCS12")
        checkNotNull(javaClass.classLoader?.getResourceAsStream("dns/test_ca.p12"))
            .use { store.load(it, "apifier-test".toCharArray()) }
        val trust = PinnedRootTrust(listOf(store.getCertificate("ca") as X509Certificate))
        val resolvers = List(3) { FakeResolver(trust) }
        return ProtectedDomainCheck(listOf(HOST), resolvers, { listOf("1.1.1.1") }, { it.run() })
            .apply { start() }
    }

    /** Disagrees with the scripted system answer, so every verdict is FAIL. */
    private class FakeResolver(trust: PinnedRootTrust) :
        TrustedResolver("fake", "https://127.0.0.1/dns-query", trust) {
        override fun query(hostname: String): DnsAnswer = DnsAnswer(listOf("8.8.8.8"), 60)
    }

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
        produce: (Request) -> Response
    ) = Step(ttfbMillis, bytesSent, bytesReceived, transferGate, produce)

    private class Step(
        val ttfbMillis: Long?,
        val bytesSent: Long,
        val bytesReceived: Long,
        val transferGate: CountDownLatch?,
        val produce: (Request) -> Response
    )

    private class FakeTransport(private val steps: List<Step>) {
        private val seen = AtomicInteger(0)

        val seenCount: Int get() = seen.get()

        fun newCall(request: Request, listener: TransportListener?): Call {
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
    ) : Call {
        private val canceled = AtomicBoolean(false)
        private val delivered = AtomicBoolean(false)

        override fun request(): Request = request

        override fun enqueue(callback: Callback) {
            thread(isDaemon = true) {
                step.ttfbMillis?.let { listener?.onResponseStarted(it) }
                try {
                    val response = step.produce(request)
                    deliver { callback.onResponse(this, response) }
                    step.transferGate?.await(5, TimeUnit.SECONDS)
                    listener?.onTransferComplete(step.bytesSent, step.bytesReceived)
                } catch (e: IOException) {
                    deliver { callback.onFailure(this, e) }
                    listener?.onTransferComplete(step.bytesSent, step.bytesReceived)
                }
            }
        }

        @Deprecated("Blocking bridge over the async path; prefer enqueue.")
        override fun execute(): Response = throw UnsupportedOperationException()

        override fun cancel() {
            canceled.set(true)
        }

        override fun isCanceled(): Boolean = canceled.get()

        private fun deliver(outcome: () -> Unit) {
            if (delivered.compareAndSet(false, true)) outcome()
        }
    }

    private companion object {
        const val HOST = "api.example.com"
    }
}
