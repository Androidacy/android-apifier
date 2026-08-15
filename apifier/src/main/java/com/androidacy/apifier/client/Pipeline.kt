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
import com.androidacy.apifier.dns.ProtectedDomainCheck
import com.androidacy.apifier.http.ApifierException
import com.androidacy.apifier.http.Call
import com.androidacy.apifier.http.Cookie
import com.androidacy.apifier.http.CookieJar
import com.androidacy.apifier.http.ErrorCode
import com.androidacy.apifier.http.Headers
import com.androidacy.apifier.http.MediaType
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.http.Response
import com.androidacy.apifier.http.ResponseBody
import com.androidacy.apifier.observe.LoggingObserver
import com.androidacy.apifier.observe.Observation
import com.androidacy.apifier.observe.Outcome
import com.androidacy.apifier.observe.RequestEvent
import com.androidacy.apifier.observe.RequestObserver
import com.androidacy.apifier.patterns.BackoffConfig
import com.androidacy.apifier.patterns.CircuitBreaker
import com.androidacy.apifier.patterns.ExponentialBackoff
import com.androidacy.apifier.progress.Progress
import com.androidacy.apifier.security.PublicSuffixList
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.withContext
import okio.Buffer
import okio.BufferedSource
import okio.ForwardingSource
import okio.Source
import okio.buffer
import java.io.IOException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Per-call inputs the caller chooses, as opposed to the process-wide [NetworkConfig]. */
internal data class CallOptions(
    /** Attempt ceiling for this call; null takes `retryConfig.maxAttempts`, and 1 means no retry. */
    val maxAttempts: Int? = null,
    /** Budget for the whole call across every attempt; null takes `timeouts.call`. */
    val callTimeoutMillis: Long? = null,
    // RequestObserver is deprecated as ApifierClient's global feed, but this per-call channel
    // has no client-wide replacement: ApifierClient.events carries no call identity to pick this
    // call's own terminal event out of.
    @Suppress("DEPRECATION")
    val observer: RequestObserver? = null,
    /** Sink for this call's byte counts; see [Requester.progress] for its contract. */
    val progress: MutableSharedFlow<Progress>? = null
)

/** Carries a call's progress sink to the transport through [Request]'s tag mechanism. */
internal class ProgressSink(val flow: MutableSharedFlow<Progress>)

/**
 * One attempt the pipeline drives.
 *
 * Separate from [Call], which is public surface: something a caller hands in as a [Call] does not
 * offer this contract.
 */
internal interface AttemptCall {

    /**
     * Runs the call and suspends until its response headers arrive, or throws the failure that
     * ended it. Cancelling the awaiting coroutine cancels the call.
     */
    suspend fun await(): Response

    fun cancel()
}

/** The transport entry the pipeline drives. [CronetTransport.newCall] satisfies it. */
internal fun interface AttemptTransport {
    fun newCall(request: Request, listener: TransportListener?): AttemptCall
}

/**
 * Per-host circuit breakers, bounded and access-ordered so a client that reaches many hosts
 * cannot grow one entry per host forever.
 */
internal class BreakerRegistry(
    private val config: CircuitBreakerConfig,
    private val maxHosts: Int = DEFAULT_MAX_HOSTS
) {

    private val breakers = object : LinkedHashMap<String, CircuitBreaker>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CircuitBreaker>): Boolean =
            size > maxHosts
    }

    /** The breaker guarding [host], or null when breaking is switched off. */
    fun forHost(host: String): CircuitBreaker? {
        if (!config.enabled) return null
        return synchronized(breakers) {
            breakers.getOrPut(host) { CircuitBreaker(config.failureThreshold, config.resetTimeoutMs) }
        }
    }

    private companion object {
        const val DEFAULT_MAX_HOSTS = 64
    }
}

/**
 * Mutable state one pipeline run shares across its stages: cancellation, the attempt the retry
 * stage has reached, and the transport call the call-timeout task has to reach.
 */
internal class PipelineCall {

    private val canceled = AtomicBoolean(false)
    private val timedOut = AtomicBoolean(false)

    @Volatile
    var inFlight: AttemptCall? = null

    @Volatile
    var attempt: Int = 0

    /** Set the instant a terminal [RequestEvent] is decided, so [Pipeline.execute]'s catch-all never double-reports it. */
    @Volatile
    var terminalEventEmitted: Boolean = false

    /**
     * Runs once the response body is finished, whether it was drained, closed or failed. The
     * body outlives [Pipeline.execute], so an owner that accounts for calls in flight cannot
     * treat the return as the end of one.
     */
    @Volatile
    var onBodyFinished: (() -> Unit)? = null

    private val bodyFinished = AtomicBoolean(false)

    val isCanceled: Boolean get() = canceled.get()

    /** True once the call-timeout task fired, which outranks whatever the transport then reports. */
    val isTimedOut: Boolean get() = timedOut.get()

    fun cancel() {
        if (canceled.compareAndSet(false, true)) inFlight?.cancel()
    }

    fun markTimedOut() {
        timedOut.set(true)
    }

    /** Called from every path that ends the body, so it has to tolerate being called again. */
    fun finishBody() {
        if (bodyFinished.compareAndSet(false, true)) onBodyFinished?.invoke()
    }
}

/**
 * Runs one logical call as ordered stages over [transport]: call timeout, trust gate, circuit
 * breaker, retry, headers, cookies, progress.
 */
internal class Pipeline(
    private val transport: AttemptTransport,
    private val config: NetworkConfig,
    private val cookieJar: CookieJar?,
    private val publicSuffixList: PublicSuffixList?,
    private val trustCheck: ProtectedDomainCheck?,
    private val breakers: BreakerRegistry,
    private val scheduler: ScheduledExecutorService,
    /** Label reported on every [RequestEvent] as the serving provider, e.g. the Cronet engine version. */
    private val provider: String,
    private val observation: Observation
) {

    init {
        require(cookieJar == null || publicSuffixList != null) {
            "a cookie jar needs a public suffix list to scope incoming cookies"
        }
        if (config.logRequests) observation.addObserver(LoggingObserver())
    }

    suspend fun execute(request: Request, options: CallOptions, call: PipelineCall): Response {
        val host = checkNotNull(request.uri.host) { "request has no host" }
        val timeoutMs = options.callTimeoutMillis ?: config.timeouts.call.inWholeMilliseconds
        val startedAt = System.currentTimeMillis()
        // An effectively unbounded budget would otherwise wrap the deadline negative.
        val deadlineAt =
            if (timeoutMs > Long.MAX_VALUE - startedAt) Long.MAX_VALUE else startedAt + timeoutMs
        val callStartNanos = System.nanoTime()
        val timeoutTask = scheduler.schedule(
            {
                call.markTimedOut()
                call.cancel()
                // A consumer that abandons a body part-read reaches neither close nor EOF, so this
                // is the only settle that call will ever get; the cancel above already released it.
                call.finishBody()
            },
            timeoutMs,
            TimeUnit.MILLISECONDS
        )

        val response = try {
            gateTrust(host, deadlineAt)
            val breaker = breakers.forHost(host)
            if (breaker != null && !breaker.checkState()) throw ApifierException.CircuitOpen(host)
            attempts(request, options, call, breaker, timeoutMs, host)
        } catch (e: Throwable) {
            timeoutTask.cancel(false)
            // Several paths end a call without reaching reportAttempt: the trust gate, the breaker,
            // a cancel or timeout landing in backoff, and consumer code throwing from a header
            // provider or a cookie jar. A cancellation is not an IOException but ends the call just
            // as a caller's own cancel does, and the observer is owed one event whatever ended it.
            if (!call.terminalEventEmitted) {
                val errorCode = when (e) {
                    is IOException -> errorCodeOf(e)
                    is CancellationException -> ErrorCode.CANCELLED
                    else -> ErrorCode.OTHER
                }
                reportTerminalFailure(host, request.method, call, errorCode, callStartNanos, options)
            }
            throw e
        }

        // The response is handed over when its headers arrive and its body is still streaming,
        // so the budget has to outlive this return; the body disarms it on close or at EOF.
        return response.newBuilder()
            .body(BudgetedBody(response.body, call, timeoutTask, timeoutMs))
            .build()
    }

    /**
     * Runs once per call and ahead of the breaker, so a host refused here never records a failure
     * against a server that did nothing wrong. The wait is capped well under the call budget
     * because a missing verdict never blocks anyway.
     *
     * [ProtectedDomainCheck.shouldBlock] already answers false when enforcement is off, so it
     * is always consulted here; only the wait is worth skipping.
     */
    private suspend fun gateTrust(host: String, deadlineAt: Long) {
        val check = trustCheck ?: return
        val budget = (deadlineAt - System.currentTimeMillis()).coerceAtMost(TRUST_VERDICT_WAIT_MS)
        // The wait parks its thread for up to TRUST_VERDICT_WAIT_MS, which the caller's own
        // dispatcher may not have to spare.
        if (check.enforcing && budget > 0) {
            withContext(Dispatchers.IO) { check.awaitVerdict(host, budget) }
        }
        if (check.shouldBlock(host)) throw ApifierException.DnsUntrusted(host)
    }

    private suspend fun attempts(
        request: Request,
        options: CallOptions,
        call: PipelineCall,
        breaker: CircuitBreaker?,
        timeoutMs: Long,
        host: String
    ): Response {
        val retry = config.retryConfig
        val maxAttempts = (options.maxAttempts ?: retry.maxAttempts).coerceAtLeast(1)
        // Sharing the ceiling keeps calculateDelay away from its -1 "attempts exceeded" sentinel.
        val backoff = ExponentialBackoff(BackoffConfig(maxAttempts = maxAttempts))
        val idempotent = request.method in IDEMPOTENT_METHODS
        var attempt = 0

        while (attempt < maxAttempts) {
            call.attempt = attempt
            surrenderIfDone(call, timeoutMs)
            val prepared = prepare(request, options)
            val metrics = AttemptMetrics()
            val attemptStartNanos = System.nanoTime()
            try {
                val response = attemptOnce(prepared, call, metrics)
                // A timeout or cancel that landed while this response was in hand outranks it, and
                // the body it carries would fail on first read anyway. Surrendering ahead of the
                // report is what keeps the reported outcome and the thrown one the same.
                if (call.isTimedOut || call.isCanceled) {
                    response.close()
                    surrenderIfDone(call, timeoutMs)
                }
                val willRetry = response.code >= 500 && attempt < maxAttempts - 1 && retry.retryOn5xx &&
                    (!retry.retryIdempotentOnly || idempotent)
                reportAttempt(
                    host, prepared.method, attempt, willRetry, metrics, attemptStartNanos,
                    Outcome.SUCCESS, errorCode = null, responseCode = response.code, call, options
                )
                if (!willRetry) {
                    if (response.code >= 500) breaker?.recordFailure() else breaker?.recordSuccess()
                    return withProgress(response, options)
                }
                response.close()
            } catch (e: IOException) {
                val retryable = e !is ApifierException || e.retryable
                val willRetry = retryable && attempt < maxAttempts - 1 &&
                    (!retry.retryIdempotentOnly || idempotent)
                reportAttempt(
                    host, prepared.method, attempt, willRetry, metrics, attemptStartNanos,
                    Outcome.FAILED, errorCode = errorCodeOf(e), responseCode = null, call, options
                )
                if (!willRetry) {
                    recordTerminalFailure(breaker, call)
                    throw surface(e, call, timeoutMs)
                }
            }
            // Outside the try/catch above, so a cancel or timeout during backoff is not
            // re-caught and reported a second time against this attempt.
            backoffWait(backoff.calculateDelay(attempt), call, timeoutMs)
            attempt++
        }
        error("retry loop ended without an outcome")
    }

    /** Builds the request the transport will see: global headers first, then jar cookies. */
    private suspend fun prepare(request: Request, options: CallOptions): Request {
        val builder = request.newBuilder()
        applyGlobalHeaders(request, builder)
        attachCookies(request, builder)
        options.progress?.let { builder.tag(ProgressSink::class.java, ProgressSink(it)) }
        return builder.build()
    }

    /** Per-request headers win: a name the request already carries is left alone. */
    private fun applyGlobalHeaders(request: Request, builder: Request.Builder) {
        for ((name, value) in config.headers) {
            if (request.header(name) == null) builder.header(name, value)
        }
        for ((name, provider) in config.dynamicHeaders) {
            if (request.header(name) == null) builder.header(name, provider())
        }
    }

    // CookieJar is a synchronous SPI over storage the consumer chose: a read can reach a disk.
    private suspend fun attachCookies(request: Request, builder: Request.Builder) {
        if (request.header("Cookie") != null) return
        val jar = cookieJar ?: return
        val cookies = withContext(Dispatchers.IO) { jar.loadForRequest(request.uri) }
        if (cookies.isEmpty()) return
        builder.header("Cookie", cookies.joinToString("; ") { "${it.name}=${it.value}" })
    }

    private suspend fun attemptOnce(
        request: Request,
        call: PipelineCall,
        metrics: AttemptMetrics
    ): Response {
        // A redirect the transport followed means the answering host is not the one addressed, and
        // its Set-Cookie headers belong to it. Saving them against the origin would let any host
        // the origin redirects to plant a cookie the origin then sends back.
        val answeredBy = AtomicReference(request.uri)

        val transportCall = transport.newCall(
            request,
            object : TransportListener {
                override fun onRedirect(hopUri: Uri, hopHeaders: Headers) = saveCookies(hopUri, hopHeaders)

                override fun onResponseStarted(ttfbMillis: Long, effectiveUri: Uri) {
                    metrics.recordResponseStarted(ttfbMillis)
                    answeredBy.set(effectiveUri)
                }

                override fun onTransferComplete(bytesSent: Long, bytesReceived: Long) {
                    metrics.recordTransferComplete(bytesSent, bytesReceived)
                }
            }
        )
        // Left set past the response too: the body is still streaming through this call, so a
        // cancel after the headers arrive has to reach it.
        call.inFlight = transportCall
        if (call.isCanceled) transportCall.cancel()

        val response = transportCall.await()
        // A cancel here, even one that lands only on the resumption after saveCookies has already
        // finished, unwinds this suspend call without touching response; nothing else on this path
        // would close it.
        try {
            withContext(Dispatchers.IO) { saveCookies(answeredBy.get(), response.headers) }
        } catch (e: Throwable) {
            response.close()
            throw e
        }
        return response
    }

    /**
     * Runs for every response the transport hands over, including ones the retry loop discards.
     * The redirect path calls this from the transport's own callback thread, which is never the
     * caller's, so only the response path hops off it.
     */
    private fun saveCookies(uri: Uri, headers: Headers) {
        val jar = cookieJar ?: return
        val psl = publicSuffixList ?: return
        val cookies = Cookie.parseAll(uri, headers, psl)
        if (cookies.isNotEmpty()) jar.saveFromResponse(uri, cookies)
    }

    /** Visible for direct testing: the wrapping it performs is otherwise unobservable from the bytes it produces. */
    internal fun withProgress(response: Response, options: CallOptions): Response {
        val sink = options.progress ?: return response
        return response.newBuilder().body(ProgressBody(response.body, sink)).build()
    }

    /**
     * A caller's cancel is our own abort and says nothing about the host. A timeout is the
     * opposite: a host that burned the whole budget without answering is what a breaker is for,
     * and it reaches here already cancelled because the timeout task cancels the transport.
     */
    private fun recordTerminalFailure(breaker: CircuitBreaker?, call: PipelineCall) {
        if (call.isCanceled && !call.isTimedOut) return
        breaker?.recordFailure()
    }

    /** Sliced so a cancel lands within one slice instead of after the whole backoff. */
    private suspend fun backoffWait(delayMs: Long, call: PipelineCall, timeoutMs: Long) {
        var remaining = delayMs
        while (remaining > 0) {
            surrenderIfDone(call, timeoutMs)
            val slice = remaining.coerceAtMost(BACKOFF_SLICE_MS)
            delay(slice)
            remaining -= slice
        }
        surrenderIfDone(call, timeoutMs)
    }

    private fun surrenderIfDone(call: PipelineCall, timeoutMs: Long) {
        if (call.isTimedOut) throw ApifierException.CallTimeout(timeoutMs)
        if (call.isCanceled) throw ApifierException.Cancelled()
    }

    /** The timeout task cancels the transport, so its cancellation error must not mask the cause. */
    private fun surface(e: IOException, call: PipelineCall, timeoutMs: Long): IOException =
        if (call.isTimedOut) ApifierException.CallTimeout(timeoutMs) else e

    /**
     * Reports one attempt. [bytesReceived] is only final once the transport's transfer-complete
     * signal fires, which for a streaming success can be well after this attempt handed its
     * response back to the caller, so the [RequestEvent] itself is built lazily off
     * [AttemptMetrics.whenTransferComplete] using the metrics that are final at that point, not
     * the ones on hand right now.
     *
     * [PipelineCall.terminalEventEmitted] is set synchronously here, at the point [willRetry] is
     * decided, not when the deferred event actually fires: [Pipeline.execute]'s catch-all reads
     * it immediately after this call returns and must already see whether this attempt is the
     * call's terminal report.
     *
     * The per-request observer is passed only on [willRetry] false, the attempt that ends the
     * logical call, since it must see exactly one event.
     */
    private fun reportAttempt(
        host: String,
        method: String,
        attemptIndex: Int,
        willRetry: Boolean,
        metrics: AttemptMetrics,
        attemptStartNanos: Long,
        outcome: Outcome,
        errorCode: ErrorCode?,
        responseCode: Int?,
        call: PipelineCall,
        options: CallOptions
    ) {
        if (!willRetry) call.terminalEventEmitted = true
        val perRequest = if (willRetry) null else options.observer ?: config.defaultObserver
        metrics.whenTransferComplete {
            observation.emit(
                RequestEvent(
                    outcome = outcome,
                    errorCode = errorCode,
                    responseCode = responseCode,
                    elapsedMillis = (System.nanoTime() - attemptStartNanos) / NANOS_PER_MILLI,
                    ttfbMillis = metrics.ttfbMillis,
                    bytesSent = metrics.bytesSent,
                    bytesReceived = metrics.bytesReceived,
                    host = host,
                    method = method,
                    attempt = attemptIndex + 1,
                    provider = provider,
                    willRetry = willRetry
                ),
                perRequest
            )
        }
    }

    /**
     * Reports a call-ending failure that never reached [reportAttempt]: the trust gate, the
     * breaker, a surrender ahead of an attempt, a cancel/timeout landing in backoff between
     * attempts, or consumer code throwing while the request is being prepared. Nothing reached the
     * transport, so there is nothing to wait on; the metrics are zero.
     */
    private fun reportTerminalFailure(
        host: String,
        method: String,
        call: PipelineCall,
        errorCode: ErrorCode,
        callStartNanos: Long,
        options: CallOptions
    ) {
        observation.emit(
            RequestEvent(
                outcome = Outcome.FAILED,
                errorCode = errorCode,
                responseCode = null,
                elapsedMillis = (System.nanoTime() - callStartNanos) / NANOS_PER_MILLI,
                ttfbMillis = null,
                bytesSent = 0L,
                bytesReceived = 0L,
                host = host,
                method = method,
                attempt = call.attempt + 1,
                provider = provider,
                willRetry = false
            ),
            options.observer ?: config.defaultObserver
        )
    }

    private fun errorCodeOf(e: IOException): ErrorCode = (e as? ApifierException)?.errorCode ?: ErrorCode.OTHER

    private companion object {
        val IDEMPOTENT_METHODS = setOf("GET", "HEAD")
        const val BACKOFF_SLICE_MS = 50L
        const val TRUST_VERDICT_WAIT_MS = 2_000L
        const val NANOS_PER_MILLI = 1_000_000L
    }
}

/**
 * Per-attempt timing and byte counts, filled from [TransportListener] as the attempt runs.
 *
 * [bytesReceived] is only correct once [recordTransferComplete] has run: the transport can
 * deliver a response (and headers-only consumers can read it) well before the network transfer
 * that fills it is over. [whenTransferComplete] is how a caller waits for that without polling or
 * blocking the thread that is about to hand the response back to its own caller.
 */
private class AttemptMetrics {
    @Volatile
    var ttfbMillis: Long? = null
        private set

    @Volatile
    var bytesSent: Long = 0L
        private set

    @Volatile
    var bytesReceived: Long = 0L
        private set

    private var completed = false
    private var onComplete: (() -> Unit)? = null

    fun recordResponseStarted(ttfbMillis: Long) {
        this.ttfbMillis = ttfbMillis
    }

    @Synchronized
    fun recordTransferComplete(bytesSent: Long, bytesReceived: Long) {
        this.bytesSent = bytesSent
        this.bytesReceived = bytesReceived
        completed = true
        onComplete?.invoke()
        onComplete = null
    }

    /** Runs [action] once [recordTransferComplete] has run; immediately if it already has. */
    @Synchronized
    fun whenTransferComplete(action: () -> Unit) {
        if (completed) action() else onComplete = action
    }
}

/**
 * Holds the call budget open while [body] streams, and disarms it once the transfer ends.
 *
 * The timeout task cancels the transport, which surfaces on this side as a cancellation, so
 * a read that fails after the deadline is retold as the timeout it really was.
 */
private class BudgetedBody(
    private val body: ResponseBody,
    private val call: PipelineCall,
    private val timeoutTask: ScheduledFuture<*>,
    private val timeoutMillis: Long
) : ResponseBody() {

    // Built eagerly, not memoized on first source() call: a lazily-created wrapper race would let
    // two callers each start buffering the same underlying source, silently splitting its bytes.
    @Suppress("DEPRECATION")
    private val bounded = bounding(body.source()).buffer()

    override fun contentType(): MediaType? = body.contentType()

    override fun contentLength(): Long = body.contentLength()

    @Suppress("OVERRIDE_DEPRECATION")
    override fun source(): BufferedSource = bounded

    override fun close() {
        disarm()
        body.close()
    }

    private fun disarm() {
        timeoutTask.cancel(false)
        call.finishBody()
    }

    private fun bounding(source: Source): Source = object : ForwardingSource(source) {
        override fun read(sink: Buffer, byteCount: Long): Long {
            val bytesRead = try {
                super.read(sink, byteCount)
            } catch (e: IOException) {
                disarm()
                throw if (call.isTimedOut) ApifierException.CallTimeout(timeoutMillis) else e
            }
            if (bytesRead == -1L) disarm()
            return bytesRead
        }
    }
}

/**
 * Reports read progress as the consumer drains [body] into [progressSink]. See [Progress] for
 * how an unknown [ResponseBody.contentLength] affects the emissions.
 */
internal class ProgressBody(
    private val body: ResponseBody,
    private val progressSink: MutableSharedFlow<Progress>
) : ResponseBody() {

    // Built eagerly for the same reason as BudgetedBody.bounded: a lazy race would let two
    // callers each buffer the same underlying source.
    @Suppress("DEPRECATION")
    private val counted = counting(body.source()).buffer()
    private val totalRead = AtomicLong(0L)
    private val lastReported = AtomicLong(-1L)
    private val eofReported = AtomicBoolean(false)

    override fun contentType(): MediaType? = body.contentType()

    override fun contentLength(): Long = body.contentLength()

    @Suppress("OVERRIDE_DEPRECATION")
    override fun source(): BufferedSource = counted

    private fun counting(source: Source): Source = object : ForwardingSource(source) {
        override fun read(sink: Buffer, byteCount: Long): Long {
            val bytesRead = super.read(sink, byteCount)
            if (bytesRead == -1L) {
                // EOF often lands on a byte total the previous read already reported, so the
                // dedup guard below would swallow the terminal signal.
                if (!eofReported.getAndSet(true)) {
                    progressSink.tryEmit(Progress(totalRead.get(), body.contentLength()))
                }
                return bytesRead
            }
            val current = totalRead.addAndGet(bytesRead)
            val last = lastReported.get()
            if (current != last && lastReported.compareAndSet(last, current)) {
                progressSink.tryEmit(Progress(current, body.contentLength()))
            }
            return bytesRead
        }
    }
}
