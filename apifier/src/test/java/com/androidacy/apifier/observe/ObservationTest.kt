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
import com.androidacy.apifier.client.NetworkConfig
import com.androidacy.apifier.client.Pipeline
import com.androidacy.apifier.client.PipelineCall
import com.androidacy.apifier.client.RetryConfig
import com.androidacy.apifier.client.TransportListener
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
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
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
        observation: Observation
    ) = Pipeline(
        transport::newCall,
        config,
        null,
        null,
        null,
        BreakerRegistry(config.circuitBreakerConfig),
        scheduler,
        "test-provider",
        observation
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
        produce: (Request) -> Response
    ) = Step(ttfbMillis, bytesSent, bytesReceived, produce)

    private class Step(
        val ttfbMillis: Long?,
        val bytesSent: Long,
        val bytesReceived: Long,
        val produce: (Request) -> Response
    )

    private class FakeTransport(private val steps: List<Step>) {
        private val seenCount = AtomicInteger(0)

        fun newCall(request: Request, listener: TransportListener?): Call {
            val index = seenCount.getAndIncrement()
            val step = steps[minOf(index, steps.size - 1)]
            return FakeCall(request, listener, step)
        }
    }

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
                    listener?.onTransferComplete(step.bytesSent, step.bytesReceived)
                    deliver { callback.onResponse(this, response) }
                } catch (e: IOException) {
                    listener?.onTransferComplete(step.bytesSent, step.bytesReceived)
                    deliver { callback.onFailure(this, e) }
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
