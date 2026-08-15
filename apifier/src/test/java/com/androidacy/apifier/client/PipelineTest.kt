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
import com.androidacy.apifier.dns.ResolverQualification
import com.androidacy.apifier.http.ApifierException
import com.androidacy.apifier.http.Cookie
import com.androidacy.apifier.http.CookieJar
import com.androidacy.apifier.http.ErrorCode
import com.androidacy.apifier.http.Headers
import com.androidacy.apifier.http.MediaType
import com.androidacy.apifier.http.Protocol
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.http.RequestBody.Companion.asRequestBody
import com.androidacy.apifier.http.RequestBody.Companion.toRequestBody
import com.androidacy.apifier.http.Response
import com.androidacy.apifier.http.ResponseBody
import com.androidacy.apifier.http.ResponseBody.Companion.asResponseBody
import com.androidacy.apifier.http.ResponseBody.Companion.toResponseBody
import com.androidacy.apifier.http.bytes
import com.androidacy.apifier.observe.Observation
import com.androidacy.apifier.observe.RequestEvent
import com.androidacy.apifier.progress.Progress
import com.androidacy.apifier.security.PublicSuffixList
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import okio.Buffer
import okio.BufferedSource
import okio.Source
import okio.Timeout
import okio.buffer
import org.chromium.net.UploadDataSink
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.coroutines.resumeWithException

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class PipelineTest {

    private val scheduler = Executors.newSingleThreadScheduledExecutor()
    private val psl = PublicSuffixList(sequenceOf("com"))
    private val observation = Observation()

    @After
    fun tearDown() {
        scheduler.shutdownNow()
        observation.close()
    }

    @Test
    fun perRequestHeaderBeatsGlobal() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(transport, config(headers = mapOf("X-K" to "global")))

        pipeline.executeBlocking(request().header("X-K", "mine").build(), CallOptions(), PipelineCall()).close()

        assertEquals(listOf("mine"), transport.seen[0].headers("X-K"))
    }

    @Test
    fun globalHeaderAppliedWhenAbsent() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(transport, config(headers = mapOf("X-K" to "global")))

        pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall()).close()

        assertEquals("global", transport.seen[0].header("X-K"))
    }

    @Test
    fun dynamicHeaderEvaluatedPerAttempt() {
        var calls = 0
        val transport = FakeTransport(listOf(step { ok(it, 500) }, step { ok(it) }))
        val pipeline = pipelineOf(
            transport,
            config(
                dynamicHeaders = mapOf("X-Nonce" to { calls++; "v$calls" }),
                retry = RetryConfig(maxAttempts = 2)
            )
        )

        pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall()).close()

        assertEquals(2, calls)
        assertEquals("v1", transport.seen[0].header("X-Nonce"))
        assertEquals("v2", transport.seen[1].header("X-Nonce"))
    }

    @Test
    fun retriedFiveHundredSavesItsCookies() {
        val jar = RecordingJar()
        val transport = FakeTransport(
            listOf(
                step { ok(it, 500, Headers.headersOf("Set-Cookie", "a=1")) },
                step { ok(it, 200, Headers.headersOf("Set-Cookie", "b=2")) }
            )
        )
        val pipeline = pipelineOf(transport, config(retry = RetryConfig(maxAttempts = 2)), jar = jar)

        pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall()).close()

        assertEquals(listOf("a", "b"), jar.saves.flatMap { (_, cookies) -> cookies.map { it.name } })
    }

    @Test
    fun storedCookiesSentWithTheRequest() {
        val jar = RecordingJar(listOf(storedCookie("sid", "abc"), storedCookie("theme", "dark")))
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(transport, config(), jar = jar)

        pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall()).close()

        assertEquals("sid=abc; theme=dark", transport.seen[0].header("Cookie"))
    }

    @Test
    fun callerCookieHeaderIsNotReplacedByTheJar() {
        val jar = RecordingJar(listOf(storedCookie("sid", "fromjar")))
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(transport, config(), jar = jar)

        pipeline.executeBlocking(
            request().header("Cookie", "sid=mine").build(),
            CallOptions(),
            PipelineCall()
        ).close()

        assertEquals("sid=mine", transport.seen[0].header("Cookie"))
    }

    @Test
    fun redirectHopCookiesCaptured() {
        val hop = Uri.parse("https://hop.example.com/first")
        val jar = RecordingJar()
        val transport = FakeTransport(
            listOf(
                hopStep { request, listener ->
                    listener?.onRedirect(hop, Headers.headersOf("Set-Cookie", "h=1"))
                    ok(request)
                }
            )
        )
        val pipeline = pipelineOf(transport, config(), jar = jar)

        pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall()).close()

        val hopSave = jar.saves.first { (uri, _) -> uri == hop }
        assertEquals(listOf("h"), hopSave.second.map { it.name })
    }

    /**
     * Production change that fails this: reverting the cookie-save hop in [Pipeline.attemptOnce]
     * back to a plain `withContext(Dispatchers.IO)`, which lets a cancel land between the save
     * completing and control returning to the caller, dropping the response before anyone can
     * close it.
     */
    @Test
    fun cancellingDuringCookieSaveDoesNotLeakTheResponseBody() {
        val enteredCookieSave = CountDownLatch(1)
        val releaseCookieSave = CountDownLatch(1)
        val body = TrackingBody()
        val jar = object : CookieJar {
            override fun loadForRequest(uri: Uri): List<Cookie> = emptyList()

            override fun saveFromResponse(uri: Uri, cookies: List<Cookie>) {
                enteredCookieSave.countDown()
                releaseCookieSave.await(5, TimeUnit.SECONDS)
            }
        }
        val transport = FakeTransport(
            listOf(step { ok(it, headers = Headers.headersOf("Set-Cookie", "a=1"), body = body) })
        )
        val pipeline = pipelineOf(transport, config(), jar = jar)
        val dispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

        try {
            runBlocking {
                val scope = CoroutineScope(dispatcher)
                val job = scope.launch {
                    val response = pipeline.execute(request().build(), CallOptions(), PipelineCall())
                    // A well-behaved caller closes as soon as it gets control back; this only
                    // runs if the response actually made it out of the pipeline.
                    response.body.close()
                }

                assertTrue(enteredCookieSave.await(5, TimeUnit.SECONDS))
                job.cancel()
                releaseCookieSave.countDown()
                job.join()

                assertTrue("cancelling during the cookie save must not drop the response body unclosed", body.closed)
            }
        } finally {
            dispatcher.close()
        }
    }

    @Test
    fun responseCookiesScopedToTheHostThatAnswered() {
        val landing = Uri.parse("https://redirected.example.com/landing")
        val jar = RecordingJar()
        val transport = FakeTransport(
            listOf(
                hopStep { request, listener ->
                    listener?.onResponseStarted(1, landing)
                    ok(request, headers = Headers.headersOf("Set-Cookie", "planted=1"))
                }
            )
        )
        val pipeline = pipelineOf(transport, config(), jar = jar)

        pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall()).close()

        val save = jar.saves.single()
        assertEquals(landing, save.first)
        assertEquals(listOf("redirected.example.com"), save.second.map { it.domain })
        assertTrue("origin jar must stay untouched", jar.saves.none { (uri, _) -> uri.host == HOST })
    }

    @Test
    fun fiveXxRetriedWithinPolicy() {
        val discarded = TrackingBody()
        val transport = FakeTransport(
            listOf(step { ok(it, 500, body = discarded) }, step { ok(it) })
        )
        val pipeline = pipelineOf(transport, config(retry = RetryConfig(maxAttempts = 2)))

        val response = pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall())

        assertEquals(200, response.code)
        assertTrue(discarded.closed)
        response.close()
    }

    @Test
    fun nonIdempotentNotRetriedWhenPolicySaysSo() {
        val transport = FakeTransport(listOf(step { throw transportFailure() }, step { ok(it) }))
        val pipeline = pipelineOf(
            transport,
            config(retry = RetryConfig(maxAttempts = 3, retryIdempotentOnly = true))
        )
        val post = request().post("x".toRequestBody(null)).build()

        assertThrows(ApifierException.Transport::class.java) {
            pipeline.executeBlocking(post, CallOptions(), PipelineCall())
        }

        assertEquals(1, transport.seen.size)
    }

    /** Fails if the idempotent method set reverts to just GET and HEAD. */
    @Test
    fun anIdempotentMethodIsRetriedAfterATransportFailure() {
        val transport = FakeTransport(listOf(step { throw transportFailure() }, step { ok(it) }))
        val pipeline = pipelineOf(
            transport,
            config(retry = RetryConfig(maxAttempts = 3, retryIdempotentOnly = true))
        )
        val put = request().put("x".toRequestBody(null)).build()

        val response = pipeline.executeBlocking(put, CallOptions(), PipelineCall())

        assertEquals(200, response.code)
        assertEquals(2, transport.seen.size)
        response.close()
    }

    @Test
    fun nonRetryableExceptionIsTerminal() {
        val transport = FakeTransport(
            listOf(step { throw ApifierException.RedirectRefused("http hop") }, step { ok(it) })
        )
        val pipeline = pipelineOf(transport, config(retry = RetryConfig(maxAttempts = 3)))

        assertThrows(ApifierException.RedirectRefused::class.java) {
            pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall())
        }

        assertEquals(1, transport.seen.size)
    }

    @Test
    fun noRetryOptionWins() {
        val transport = FakeTransport(listOf(step { ok(it, 500) }))
        val pipeline = pipelineOf(transport, config(retry = RetryConfig(maxAttempts = 3)))

        val response = pipeline.executeBlocking(request().build(), CallOptions(maxAttempts = 1), PipelineCall())

        assertEquals(500, response.code)
        assertEquals(1, transport.seen.size)
        response.close()
    }

    /** Also fails if the gate stops running ahead of the breaker, or if a refusal is retried. */
    @Test
    fun anUntrustedResolverRefusesCallsWhenEnforcing() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val breakers = BreakerRegistry(CircuitBreakerConfig(failureThreshold = 1))
        val breaker = checkNotNull(breakers.forHost(HOST))
        val pipeline = pipelineOf(
            transport,
            config(retry = RetryConfig(maxAttempts = 3), enforceResolver = true),
            breakers = breakers,
            qualification = untrustedQualification()
        )

        val thrown = assertThrows(ApifierException.DnsUntrusted::class.java) {
            pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall())
        }

        assertEquals(HOST, thrown.host)
        assertEquals(0, transport.seen.size)
        assertTrue(breaker.isClosed)

        // An open breaker on the same host would answer first if the gate ran second.
        breaker.recordFailure()
        assertThrows(ApifierException.DnsUntrusted::class.java) {
            pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall())
        }
    }

    /** Fails if enforcement becomes unconditional. */
    @Test
    fun anUntrustedResolverDoesNotRefuseCallsWhenNotEnforcing() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(transport, config(), qualification = untrustedQualification())

        val response = pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall())

        assertEquals(200, response.code)
        assertEquals(1, transport.seen.size)
        response.close()
    }

    /** Fails if a verdict that has not landed blocks a caller who never asked for enforcement. */
    @Test
    fun aPendingVerdictNeverBlocksANonEnforcingClient() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(transport, config(), qualification = pendingQualification())

        val response = pipeline.executeBlocking(
            request().build(),
            CallOptions(callTimeoutMillis = PENDING_BUDGET_MS),
            PipelineCall()
        )

        assertEquals(200, response.code)
        response.close()
    }

    /** Fails if the wait gets a budget of its own instead of what is left of the call's. */
    @Test
    fun aPendingVerdictWaitsOnTheCallBudgetWhenEnforcing() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(
            transport,
            config(enforceResolver = true),
            qualification = pendingQualification()
        )

        val startedAt = System.nanoTime()
        assertThrows(ApifierException.DnsUntrusted::class.java) {
            pipeline.executeBlocking(
                request().build(),
                CallOptions(callTimeoutMillis = PENDING_BUDGET_MS),
                PipelineCall()
            )
        }
        val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000

        assertTrue("the gate gave up after ${elapsedMs}ms", elapsedMs >= PENDING_BUDGET_MS - 100)
        assertEquals(0, transport.seen.size)
    }

    /** Fails if an effectively unbounded budget is handed to the wait as it stands, wrapping its deadline negative. */
    @Test
    fun anEffectivelyUnboundedCallBudgetStillWaitsForTheVerdict() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val answer = CountDownLatch(1)
        val probes = Executors.newCachedThreadPool()
        val qualification = ResolverQualification(
            resolve = { host ->
                answer.await(10, TimeUnit.SECONDS)
                if (host.endsWith(INVALID_SUFFIX)) emptyList() else listOf(PUBLIC_ADDRESS)
            },
            executor = probes,
            junkLabelCount = 1,
            canaries = listOf(CANARY),
            // The wait reads its clock after the gate has computed the budget, so this offset
            // stands in for that gap and makes an unguarded budget overflow every run.
            clock = { System.currentTimeMillis() + CLOCK_SKEW_MS }
        )
        val pipeline = pipelineOf(transport, config(enforceResolver = true), qualification = qualification)
        thread(isDaemon = true) {
            Thread.sleep(200)
            answer.countDown()
        }

        val response = pipeline.executeBlocking(
            request().build(),
            CallOptions(callTimeoutMillis = Long.MAX_VALUE),
            PipelineCall()
        )

        assertEquals(200, response.code)
        response.close()
        probes.shutdownNow()
    }

    /** Fails if the gate drops its per-host consult and rules on the global verdict alone. */
    @Test
    fun aHostUntrustedOnFirstSightIsRefusedWhenEnforcing() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val qualification = qualification { host ->
            when {
                host == HOST -> listOf("192.168.1.1")
                host.endsWith(INVALID_SUFFIX) -> emptyList()
                else -> listOf(PUBLIC_ADDRESS)
            }
        }
        val pipeline = pipelineOf(transport, config(enforceResolver = true), qualification = qualification)

        val thrown = assertThrows(ApifierException.DnsUntrusted::class.java) {
            pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall())
        }

        assertEquals(HOST, thrown.host)
        assertEquals(0, transport.seen.size)
    }

    /** Fails if the per-host check runs for a caller who never asked for enforcement. */
    @Test
    fun perHostChecksDoNotRunWithoutEnforcement() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val resolved = CopyOnWriteArrayList<String>()
        val qualification = qualification { host ->
            resolved += host
            if (host.endsWith(INVALID_SUFFIX)) emptyList() else listOf(PUBLIC_ADDRESS)
        }
        val pipeline = pipelineOf(transport, config(), qualification = qualification)

        val response = pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall())

        assertEquals(200, response.code)
        assertFalse("the call host was resolved: $resolved", resolved.contains(HOST))
        response.close()
    }

    /** Fails if the gate drops its pin consult: a pinned host resolving outside its pins must never reach the transport. */
    @Test
    fun aPinnedHostResolvingOutsideItsPinsIsRefusedByTheGate() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(
            transport,
            config(hostIpPins = mapOf(PIN_HOST to setOf("203.0.113.10")))
        )

        val thrown = assertThrows(ApifierException.DnsUntrusted::class.java) {
            pipeline.executeBlocking(
                Request.Builder().url("https://$PIN_HOST/resource").build(),
                CallOptions(),
                PipelineCall()
            )
        }

        assertEquals(PIN_HOST, thrown.host)
        assertEquals(0, transport.seen.size)
    }

    /** Fails if enforcement goes back to depending on the flag once a pin exists anywhere on the client. */
    @Test
    fun pinsForceEnforcementEvenWithTheFlagOff() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(
            transport,
            config(enforceResolver = false, hostIpPins = mapOf("other.example.com" to setOf(PUBLIC_ADDRESS))),
            qualification = untrustedQualification()
        )

        val thrown = assertThrows(ApifierException.DnsUntrusted::class.java) {
            pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall())
        }

        assertEquals(HOST, thrown.host)
        assertEquals(0, transport.seen.size)
    }

    /** Fails if the verdict wait parks its thread instead of suspending. */
    @Test
    fun trustWaitDoesNotBlockTheCallingThread() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(
            transport,
            config(enforceResolver = true),
            qualification = pendingQualification()
        )
        val dispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
        val scope = CoroutineScope(dispatcher)
        val done = CountDownLatch(1)

        scope.launch {
            runCatching {
                pipeline.execute(
                    request().build(),
                    CallOptions(callTimeoutMillis = PENDING_BUDGET_MS),
                    PipelineCall()
                ).close()
            }
            done.countDown()
        }
        val marker = CountDownLatch(1)
        scope.launch { marker.countDown() }

        assertTrue(
            "the trust wait parked the calling dispatcher",
            marker.await(1, TimeUnit.SECONDS)
        )
        assertTrue(done.await(10, TimeUnit.SECONDS))
        dispatcher.close()
    }

    @Test
    fun circuitOpenShortCircuits() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val breakers = BreakerRegistry(CircuitBreakerConfig(failureThreshold = 1))
        breakers.forHost(HOST)?.recordFailure()
        val pipeline = pipelineOf(transport, config(), breakers = breakers)

        val thrown = assertThrows(ApifierException.CircuitOpen::class.java) {
            pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall())
        }

        assertEquals(HOST, thrown.host)
        assertEquals(0, transport.seen.size)
    }

    @Test
    fun breakerRecordsOneOutcomePerCall() {
        val transport = FakeTransport(
            listOf(step { ok(it, 500) }, step { ok(it, 500) }, step { ok(it) })
        )
        val breakers = BreakerRegistry(CircuitBreakerConfig(failureThreshold = 1))
        val breaker = checkNotNull(breakers.forHost(HOST))
        val pipeline = pipelineOf(
            transport,
            config(retry = RetryConfig(maxAttempts = 3)),
            breakers = breakers
        )

        pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall()).close()

        assertEquals(3, transport.seen.size)
        assertTrue(breaker.isClosed)
    }

    @Test
    fun callTimeoutSpansAttempts() {
        val transport = FakeTransport(
            listOf(step(delayMs = 300) { ok(it, 500) }, step(delayMs = 300) { ok(it, 500) })
        )
        val breakers = BreakerRegistry(CircuitBreakerConfig(failureThreshold = 1))
        val breaker = checkNotNull(breakers.forHost(HOST))
        val pipeline = pipelineOf(
            transport,
            config(retry = RetryConfig(maxAttempts = 3)),
            breakers = breakers
        )

        assertThrows(ApifierException.CallTimeout::class.java) {
            pipeline.executeBlocking(request().build(), CallOptions(callTimeoutMillis = 1500), PipelineCall())
        }

        assertEquals(2, transport.seen.size)
        assertTrue("a host that burned the whole budget is a breaker failure", breaker.isOpen)
    }

    @Test
    fun callTimeoutBoundsTheResponseBody() {
        val transport = FakeTransport(listOf(slowBodyStep()))
        val pipeline = pipelineOf(transport, config())

        val response =
            pipeline.executeBlocking(request().build(), CallOptions(callTimeoutMillis = 300), PipelineCall())
        val started = System.nanoTime()
        assertThrows(ApifierException.CallTimeout::class.java) { runBlocking { response.body.bytes() } }
        val elapsedMs = (System.nanoTime() - started) / 1_000_000

        assertTrue("body failed after ${elapsedMs}ms", elapsedMs < 3_000)
    }

    @Test
    fun timeoutRacingTheHandoverOutranksTheResponse() {
        val call = PipelineCall()
        val transport = FakeTransport(
            listOf(
                step {
                    call.markTimedOut()
                    ok(it)
                }
            )
        )
        val pipeline = pipelineOf(transport, config())

        assertThrows(ApifierException.CallTimeout::class.java) {
            pipeline.executeBlocking(request().build(), CallOptions(), call)
        }
    }

    /** Production change that fails this: awaiting the attempt on the calling thread, as a latch does. */
    @Test
    fun oneAttemptOccupiesNoThreadWhileTheTransportIsInFlight() {
        val transport = FakeTransport(listOf(step(delayMs = 1_000) { ok(it) }))
        val pipeline = pipelineOf(transport, config())
        val dispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

        try {
            runBlocking {
                val scope = CoroutineScope(dispatcher)
                val call = scope.async {
                    pipeline.execute(request().build(), CallOptions(), PipelineCall())
                }
                val ranDuringTheAttempt = CompletableDeferred<Unit>()
                scope.launch { ranDuringTheAttempt.complete(Unit) }

                withTimeout(500) { ranDuringTheAttempt.await() }

                assertTrue("the attempt must still be in flight", call.isActive)
                call.await().close()
            }
        } finally {
            dispatcher.close()
        }
    }

    /** Production change that fails this: a Thread.sleep backoff, which holds the thread for the whole delay. */
    @Test
    fun retryBackoffDoesNotOccupyAThread() {
        val firstAttemptAnswered = CountDownLatch(1)
        val transport = FakeTransport(
            listOf(step { firstAttemptAnswered.countDown(); ok(it, 500) }, step { ok(it) })
        )
        val pipeline = pipelineOf(transport, config(retry = RetryConfig(maxAttempts = 2)))
        val dispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

        try {
            runBlocking {
                val scope = CoroutineScope(dispatcher)
                val call = scope.async {
                    pipeline.execute(request().build(), CallOptions(), PipelineCall())
                }
                assertTrue(firstAttemptAnswered.await(5, TimeUnit.SECONDS))
                // The retry stage has to have resumed and entered backoff before the task below
                // is queued behind it, or it would win the dispatcher without proving anything.
                Thread.sleep(150)
                val ranDuringBackoff = CompletableDeferred<Unit>()
                scope.launch { ranDuringBackoff.complete(Unit) }

                withTimeout(400) { ranDuringBackoff.await() }

                assertEquals("the second attempt must not have started yet", 1, transport.seen.size)
                call.await().close()
            }
        } finally {
            dispatcher.close()
        }
    }

    /** Production change that fails this: removing the cancel guard in recordTerminalFailure. */
    @Test
    fun nonTimeoutCancelDoesNotChargeTheBreaker() {
        val transport = FakeTransport(listOf(step(delayMs = 5_000) { ok(it) }))
        val breakers = BreakerRegistry(CircuitBreakerConfig(failureThreshold = 1))
        val breaker = checkNotNull(breakers.forHost(HOST))
        val pipeline = pipelineOf(transport, config(), breakers = breakers)
        val call = PipelineCall()
        thread(isDaemon = true) {
            Thread.sleep(150)
            call.cancel()
        }

        assertThrows(ApifierException.Cancelled::class.java) {
            pipeline.executeBlocking(request().build(), CallOptions(), call)
        }

        assertTrue("a caller's own cancel says nothing about the host", breaker.isClosed)
    }

    /** Production change that fails this: disarming the budget when execute returns instead of at close. */
    @Test
    fun budgetSurvivesTheReturnAndDisarmsAtClose() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(transport, config())
        val streaming = PipelineCall()
        val closed = PipelineCall()

        pipeline.executeBlocking(request().build(), CallOptions(callTimeoutMillis = 200), streaming)
        pipeline.executeBlocking(request().build(), CallOptions(callTimeoutMillis = 200), closed).close()
        Thread.sleep(600)

        assertTrue("a body still in hand leaves the budget armed", streaming.isTimedOut)
        assertFalse("closing the body disarms the budget", closed.isTimedOut)
    }

    /**
     * Two racing callers reading a plain memoization field can each observe it unset and build
     * their own wrapper, splitting the underlying source between two owners.
     */
    @Test
    fun concurrentSourceAccessReturnsOneWrapper() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(transport, config())
        val response = pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall())
        val body = response.body

        val barrier = CyclicBarrier(2)
        val results = arrayOfNulls<BufferedSource>(2)
        val readers = (0 until 2).map { i ->
            thread {
                barrier.await()
                results[i] = body.source()
            }
        }
        readers.forEach { it.join() }

        assertSame(results[0], results[1])
        response.close()
    }

    /** Production changes that fail this: dropping the settle from the timeout task, or settling it unguarded. */
    @Test
    fun settlingTwiceIsHarmless() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(transport, config())
        val settles = AtomicInteger()
        val call = PipelineCall()
        call.onBodyFinished = { settles.incrementAndGet() }

        val response = pipeline.executeBlocking(request().build(), CallOptions(callTimeoutMillis = 150), call)
        Thread.sleep(500)
        val afterBudget = settles.get()
        response.close()

        assertEquals("the budget must settle a body the consumer abandoned", 1, afterBudget)
        assertEquals("closing an already settled body must not settle it again", 1, settles.get())
    }

    /**
     * An interrupted blocking caller ends its call with a coroutine cancellation. Production
     * changes that fail this: reporting only IOException failures from execute's catch-all, which
     * a cancellation is not; or leaving the budget armed on the way out.
     */
    @Suppress("DEPRECATION")
    @Test
    fun interruptedCallStillReportsItsEndAndDisarmsTheBudget() {
        val transport = FakeTransport(listOf(step { ok(it, 500) }, step { ok(it) }))
        val events = CopyOnWriteArrayList<RequestEvent>()
        observation.addObserver { events.add(it) }
        val pipeline = pipelineOf(transport, config(retry = RetryConfig(maxAttempts = 2)))
        val call = PipelineCall()
        val outcome = AtomicReference<Throwable?>()
        val worker = thread(isDaemon = true) {
            outcome.set(
                runCatching {
                    pipeline.executeBlocking(request().build(), CallOptions(callTimeoutMillis = 400), call).close()
                }.exceptionOrNull()
            )
        }

        Thread.sleep(200)
        worker.interrupt()
        worker.join(5_000)
        // Past the budget deadline: a timer nobody disarmed has fired by now.
        Thread.sleep(500)

        assertTrue("got ${outcome.get()}", outcome.get() is ApifierException.Cancelled)
        assertFalse("an interrupted call must not leave its budget armed", call.isTimedOut)
        val terminal = events.filter { !it.willRetry }
        assertEquals("one terminal event, got $terminal", 1, terminal.size)
        assertEquals(ErrorCode.CANCELLED, terminal[0].errorCode)
    }

    @Test
    fun interruptedBackoffDoesNotBlameTheHost() {
        val transport = FakeTransport(listOf(step { ok(it, 500) }, step { ok(it) }))
        val breakers = BreakerRegistry(CircuitBreakerConfig(failureThreshold = 1))
        val breaker = checkNotNull(breakers.forHost(HOST))
        val pipeline = pipelineOf(
            transport,
            config(retry = RetryConfig(maxAttempts = 2)),
            breakers = breakers
        )
        val outcome = AtomicReference<Throwable?>()
        val worker = thread(isDaemon = true) {
            outcome.set(
                runCatching {
                    pipeline.executeBlocking(request().build(), CallOptions(), PipelineCall()).close()
                }.exceptionOrNull()
            )
        }

        Thread.sleep(200)
        worker.interrupt()
        worker.join(5_000)

        assertTrue("got ${outcome.get()}", outcome.get() is ApifierException.Cancelled)
        assertTrue(breaker.isClosed)
    }

    @Test
    fun cancelDuringBackoffSurrenders() {
        val transport = FakeTransport(listOf(step { ok(it, 500) }, step { ok(it) }))
        val pipeline = pipelineOf(transport, config(retry = RetryConfig(maxAttempts = 2)))
        val call = PipelineCall()
        thread(isDaemon = true) {
            Thread.sleep(150)
            call.cancel()
        }

        val started = System.nanoTime()
        assertThrows(ApifierException.Cancelled::class.java) {
            pipeline.executeBlocking(request().build(), CallOptions(), call)
        }
        val elapsedMs = (System.nanoTime() - started) / 1_000_000

        assertTrue("surrendered after ${elapsedMs}ms", elapsedMs < 700)
    }

    /** Production change that fails this: restoring the dedup guard over the EOF emission. */
    @Test
    fun downloadSinkEmitsTerminalTotalAtEof() = runTest {
        val payload = ByteArray(30) { it.toByte() }
        val (sink, collected) = collectingSink(this)

        ProgressBody(chunkedBody(payload, 10), sink).source().readByteArray()

        // The last data-bearing read already reports 30, so a dedup guard over the EOF
        // emission would leave the same final value behind; only the count of emissions
        // (one extra at EOF, on top of one per 10-byte chunk) tells the two apart.
        assertEquals(4, collected.size)
        assertEquals(30L, collected.last().bytesTransferred)
    }

    /** Production change that fails this: inventing a total for unknown-length bodies. */
    @Test
    fun unknownLengthBodyEmitsWithoutTerminal() = runTest {
        val payload = ByteArray(20) { it.toByte() }
        val (sink, collected) = collectingSink(this)

        ProgressBody(chunkedBody(payload, 6, contentLength = -1L), sink).source().readByteArray()

        assertTrue(collected.isNotEmpty())
        assertTrue(
            "no emission may claim a total when none is known",
            collected.none { it.bytesTransferred == it.contentLength }
        )
    }

    /** Production change that fails this: inserting ProgressBody unconditionally. */
    @Test
    fun absentSinkInsertsNoProgressLayer() {
        val pipeline = pipelineOf(FakeTransport(listOf(step { ok(it) })), config())
        val response = ok(request().build(), body = chunkedBody(ByteArray(4), 4))

        assertSame(response, pipeline.withProgress(response, CallOptions()))
    }

    /** Production change that fails this: leaving the tag unwritten in prepare. */
    @Test
    fun progressSinkReachesTheTransportThroughPrepare() {
        val transport = FakeTransport(listOf(step { ok(it) }))
        val pipeline = pipelineOf(transport, config())
        val sink = MutableSharedFlow<Progress>(extraBufferCapacity = 1)

        pipeline.executeBlocking(request().build(), CallOptions(progress = sink), PipelineCall()).close()

        assertSame(sink, transport.seen[0].tag(ProgressSink::class.java)?.flow)
    }

    /** Production change that fails this: starting the download emitter before the upload phase ends. */
    @Test
    fun uploadThenDownloadReportSequentiallyIntoOneSink() = runTest {
        val file = File.createTempFile("pipeline-progress-test", ".bin")
            .apply { writeBytes(ByteArray(20) { it.toByte() }) }
        try {
            val (sink, collected) = collectingSink(this)
            val uploadProvider = StreamingUploadProvider(file.asRequestBody(), sink)
            val uploadSink = RecordingUploadSink()
            val chunkSize = 8
            // A known content length never sets the finalChunk flag (that only applies to
            // chunked bodies), so the read count is computed from the file length instead.
            val reads = ((file.length() + chunkSize - 1) / chunkSize).toInt()
            repeat(reads) { uploadProvider.read(uploadSink, ByteBuffer.allocate(chunkSize)) }
            val uploadEmissionCount = collected.size
            assertTrue("the upload phase must have reported before the download starts", uploadEmissionCount > 0)

            ProgressBody(chunkedBody(ByteArray(10) { it.toByte() }, 4, contentLength = 10L), sink)
                .source().readByteArray()

            val uploadPhase = collected.subList(0, uploadEmissionCount)
            val downloadPhase = collected.subList(uploadEmissionCount, collected.size)
            assertTrue(uploadPhase.all { it.contentLength == 20L })
            assertTrue(downloadPhase.isNotEmpty())
            assertTrue(downloadPhase.all { it.contentLength == 10L })
        } finally {
            file.delete()
        }
    }

    /**
     * Registers a live collector before returning, matching the shape [Requester.progress]'s
     * KDoc documents: a sink with room in its buffer, subscribed ahead of any emission.
     */
    private fun collectingSink(scope: kotlinx.coroutines.test.TestScope): Pair<MutableSharedFlow<Progress>, List<Progress>> {
        val sink = MutableSharedFlow<Progress>(extraBufferCapacity = 32)
        val collected = mutableListOf<Progress>()
        CoroutineScope(UnconfinedTestDispatcher(scope.testScheduler)).launch { sink.collect { collected += it } }
        return sink to collected
    }

    private class RecordingUploadSink : UploadDataSink() {
        override fun onReadSucceeded(finalChunk: Boolean) = Unit

        override fun onReadError(exception: Exception) = throw exception

        override fun onRewindSucceeded() = Unit

        override fun onRewindError(exception: Exception) = throw exception
    }

    /**
     * Runs [Pipeline.execute] synchronously, converting an interrupt into a cancellation the way
     * the deprecated `ClientCall.execute` bridge does, so tests can drive a blocking caller with
     * [Thread.interrupt] without depending on `ApifierClient`.
     */
    private fun Pipeline.executeBlocking(request: Request, options: CallOptions, call: PipelineCall): Response =
        try {
            runBlocking { execute(request, options, call) }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            call.cancel()
            throw ApifierException.Cancelled()
        }

    private fun request(): Request.Builder = Request.Builder().url("https://$HOST/resource")

    private fun config(
        headers: Map<String, String> = emptyMap(),
        dynamicHeaders: Map<String, () -> String> = emptyMap(),
        retry: RetryConfig = RetryConfig(),
        enforceResolver: Boolean = false,
        hostIpPins: Map<String, Set<String>> = emptyMap()
    ) = NetworkConfig(
        headers = headers,
        dynamicHeaders = dynamicHeaders,
        retryConfig = retry,
        ensureTrustworthyResolver = enforceResolver,
        hostIpPins = hostIpPins
    )

    private fun pipelineOf(
        transport: FakeTransport,
        config: NetworkConfig,
        jar: CookieJar? = null,
        breakers: BreakerRegistry = BreakerRegistry(config.circuitBreakerConfig),
        qualification: ResolverQualification = qualification(CLEAN_RESOLVE)
    ) = Pipeline(
        transport::newCall,
        config,
        jar,
        if (jar == null) null else psl,
        qualification,
        breakers,
        scheduler,
        "test-provider",
        observation
    )

    private fun ok(
        request: Request,
        code: Int = 200,
        headers: Headers = Headers.headersOf(),
        body: ResponseBody = ByteArray(0).toResponseBody(null)
    ): Response = Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_2)
        .code(code)
        .message("")
        .headers(headers)
        .body(body)
        .build()

    private fun storedCookie(name: String, value: String): Cookie = Cookie.Builder()
        .name(name)
        .value(value)
        .hostOnlyDomain(HOST)
        .expiresAt(Long.MAX_VALUE)
        .build()

    private fun transportFailure() = ApifierException.Transport(
        errorCode = ErrorCode.CONNECTION_RESET,
        cronetErrorCode = 0,
        immediatelyRetryable = true,
        message = "reset",
        cause = null
    )

    private fun step(delayMs: Long = 0, produce: (Request) -> Response) =
        Step(delayMs) { request, _, _ -> produce(request) }

    private fun hopStep(produce: (Request, TransportListener?) -> Response) =
        Step(0) { request, listener, _ -> produce(request, listener) }

    /** Runs every probe on the calling thread, so a verdict is settled by the time a read returns. */
    private fun qualification(resolve: (String) -> List<String>) = ResolverQualification(
        resolve = resolve,
        executor = Executor { it.run() },
        junkLabelCount = 1,
        canaries = listOf(CANARY),
        clock = { 0L }
    )

    /** An answer for a name that is never delegated, which is a resolver rewriting NXDOMAIN. */
    private fun untrustedQualification() = qualification { listOf(PUBLIC_ADDRESS) }

    /** No verdict ever arrives: the probe executor drops the work it is handed. */
    private fun pendingQualification() = ResolverQualification(
        resolve = { emptyList() },
        executor = Executor { },
        junkLabelCount = 1,
        canaries = listOf(CANARY),
        clock = System::currentTimeMillis
    )

    /** A body that only ends when the transport is cancelled, the way [BodyPipe] behaves. */
    private fun slowBodyStep() = Step(0) { request, _, cancelSignal ->
        val source = object : Source {
            override fun read(sink: Buffer, byteCount: Long): Long {
                if (cancelSignal.await(10, TimeUnit.SECONDS)) throw ApifierException.Cancelled()
                return -1
            }

            override fun timeout(): Timeout = Timeout.NONE

            override fun close() = Unit
        }
        ok(request, body = source.buffer().asResponseBody(null, -1L))
    }

    private fun chunkedBody(payload: ByteArray, chunk: Int, contentLength: Long = payload.size.toLong()): ResponseBody {
        val source = object : Source {
            private var offset = 0

            override fun read(sink: Buffer, byteCount: Long): Long {
                if (offset >= payload.size) return -1
                val count = minOf(chunk.toLong(), (payload.size - offset).toLong(), byteCount).toInt()
                sink.write(payload, offset, count)
                offset += count
                return count.toLong()
            }

            override fun timeout(): Timeout = Timeout.NONE

            override fun close() = Unit
        }
        return source.buffer().asResponseBody(null, contentLength)
    }

    private class RecordingJar(private val stored: List<Cookie> = emptyList()) : CookieJar {
        val saves = mutableListOf<Pair<Uri, List<Cookie>>>()

        override fun loadForRequest(uri: Uri): List<Cookie> = stored

        override fun saveFromResponse(uri: Uri, cookies: List<Cookie>) {
            synchronized(saves) { saves.add(uri to cookies) }
        }
    }

    private class TrackingBody : ResponseBody() {
        var closed = false
            private set

        private val payload = Buffer().writeUtf8("payload")

        override fun contentType(): MediaType? = null

        override fun contentLength(): Long = payload.size

        @Suppress("OVERRIDE_DEPRECATION")
        override fun source(): BufferedSource = payload

        override fun close() {
            closed = true
            payload.close()
        }
    }

    private class Step(
        val delayMs: Long,
        val produce: (Request, TransportListener?, CountDownLatch) -> Response
    )

    private class FakeTransport(private val steps: List<Step>) {
        val seen = mutableListOf<Request>()

        fun newCall(request: Request, listener: TransportListener?): AttemptCall {
            val step = synchronized(seen) {
                seen.add(request)
                steps[minOf(seen.size - 1, steps.size - 1)]
            }
            return FakeCall(request, listener, step)
        }
    }

    /**
     * Mirrors the contract [CronetCall] gives the pipeline: exactly one terminal outcome, and a
     * cancel that produces one promptly instead of waiting out the scripted delay. The scripted
     * work runs on its own thread, so awaiting it never occupies the caller's.
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
                if (cancelSignal.await(step.delayMs, TimeUnit.MILLISECONDS)) {
                    deliver { continuation.resumeWithException(ApifierException.Cancelled()) }
                    return@thread
                }
                try {
                    val response = step.produce(request, listener, cancelSignal)
                    deliver { continuation.resume(response) { _, undelivered, _ -> undelivered.close() } }
                } catch (e: IOException) {
                    deliver { continuation.resumeWithException(e) }
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
        // Resolved by the OS locally, so the pin gate needs no real network to run.
        const val PIN_HOST = "localhost"
        const val CANARY = "canary.example.org"
        const val INVALID_SUFFIX = ".invalid"
        const val PUBLIC_ADDRESS = "93.184.216.34"
        const val PENDING_BUDGET_MS = 400L
        const val CLOCK_SKEW_MS = 100L
        val CLEAN_RESOLVE: (String) -> List<String> = { host ->
            if (host.endsWith(INVALID_SUFFIX)) emptyList() else listOf(PUBLIC_ADDRESS)
        }
    }
}
