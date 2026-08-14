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
import com.androidacy.apifier.http.Callback
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
import com.androidacy.apifier.progress.ProgressListener
import com.androidacy.apifier.security.PublicSuffixList
import okio.Buffer
import okio.BufferedSource
import okio.ForwardingSource
import okio.Source
import okio.buffer
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Per-call inputs the caller chooses, as opposed to the process-wide [NetworkConfig]. */
data class CallOptions(
    /** Attempt ceiling for this call; null takes `retryConfig.maxAttempts`, and 1 means no retry. */
    val maxAttempts: Int? = null,
    /** Budget for the whole call across every attempt; null takes `timeouts.call`. */
    val callTimeoutMillis: Long? = null,
    /** Sees exactly one event for this call: the completing attempt, or the last failure. */
    val observer: RequestObserver? = null
)

/** The transport entry the pipeline drives. [CronetTransport.newCall] satisfies it. */
internal fun interface AttemptTransport {
    fun newCall(request: Request, listener: TransportListener?): Call
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
    var inFlight: Call? = null

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
 *
 * [execute] blocks and belongs on a worker thread.
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

    fun execute(request: Request, options: CallOptions, call: PipelineCall): Response {
        val host = checkNotNull(request.uri.host) { "request has no host" }
        val timeoutMs = options.callTimeoutMillis ?: config.timeouts.call.inWholeMilliseconds
        val deadlineAt = System.currentTimeMillis() + timeoutMs
        val callStartNanos = System.nanoTime()
        val timeoutTask = scheduler.schedule(
            {
                call.markTimedOut()
                call.cancel()
            },
            timeoutMs,
            TimeUnit.MILLISECONDS
        )

        val response = try {
            gateTrust(host, deadlineAt)
            val breaker = breakers.forHost(host)
            if (breaker != null && !breaker.checkState()) throw ApifierException.CircuitOpen(host)
            attempts(request, options, call, breaker, timeoutMs, deadlineAt, host)
        } catch (e: Throwable) {
            timeoutTask.cancel(false)
            // The trust gate, the breaker, a surrender ahead of an attempt, and a cancel or
            // timeout landing in backoff between attempts all end the call without ever reaching
            // reportAttempt. terminalEventEmitted is only true when reportAttempt already covered
            // this outcome, which keeps this from doubling that report.
            if (e is IOException && !call.terminalEventEmitted) {
                reportTerminalFailure(host, request.method, call, errorCodeOf(e), callStartNanos, options)
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
    private fun gateTrust(host: String, deadlineAt: Long) {
        val check = trustCheck ?: return
        val budget = (deadlineAt - System.currentTimeMillis()).coerceAtMost(TRUST_VERDICT_WAIT_MS)
        if (check.enforcing && budget > 0) check.awaitVerdict(host, budget)
        if (check.shouldBlock(host)) throw ApifierException.DnsUntrusted(host)
    }

    private fun attempts(
        request: Request,
        options: CallOptions,
        call: PipelineCall,
        breaker: CircuitBreaker?,
        timeoutMs: Long,
        deadlineAt: Long,
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
            val prepared = prepare(request)
            val metrics = AttemptMetrics()
            val attemptStartNanos = System.nanoTime()
            try {
                val response = attemptOnce(prepared, call, timeoutMs, deadlineAt, metrics)
                val willRetry = response.code >= 500 && attempt < maxAttempts - 1 && retry.retryOn5xx &&
                    (!retry.retryIdempotentOnly || idempotent)
                reportAttempt(
                    host, prepared.method, attempt, willRetry, metrics, attemptStartNanos,
                    Outcome.SUCCESS, errorCode = null, responseCode = response.code, call, options
                )
                if (!willRetry) {
                    // A timeout that landed while this response was in hand outranks it, and the
                    // body it carries would fail on first read anyway.
                    if (call.isTimedOut || call.isCanceled) {
                        response.close()
                        surrenderIfDone(call, timeoutMs)
                    }
                    if (response.code >= 500) breaker?.recordFailure() else breaker?.recordSuccess()
                    return withProgress(prepared, response)
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
            // Reached only for an attempt that will be retried. Backoff runs outside the try/catch
            // above so a cancel or timeout here escapes straight to execute()'s catch instead of
            // being re-caught by the same clause and reported a second time against this attempt.
            backoffSleep(backoff.calculateDelay(attempt), call, timeoutMs)
            attempt++
        }
        // The last attempt takes neither retry branch, so the loop always returns or throws.
        error("retry loop ended without an outcome")
    }

    /** Builds the request the transport will see: global headers first, then jar cookies. */
    private fun prepare(request: Request): Request {
        val builder = request.newBuilder()
        applyGlobalHeaders(request, builder)
        attachCookies(request, builder)
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

    private fun attachCookies(request: Request, builder: Request.Builder) {
        if (request.header("Cookie") != null) return
        val cookies = cookieJar?.loadForRequest(request.uri).orEmpty()
        if (cookies.isEmpty()) return
        builder.header("Cookie", cookies.joinToString("; ") { "${it.name}=${it.value}" })
    }

    private fun attemptOnce(
        request: Request,
        call: PipelineCall,
        timeoutMs: Long,
        deadlineAt: Long,
        metrics: AttemptMetrics
    ): Response {
        val done = CountDownLatch(1)
        val result = AtomicReference<Response?>()
        val failure = AtomicReference<IOException?>()

        val transportCall = transport.newCall(
            request,
            object : TransportListener {
                override fun onRedirect(hopUri: Uri, hopHeaders: Headers) = saveCookies(hopUri, hopHeaders)

                override fun onResponseStarted(ttfbMillis: Long) {
                    metrics.recordResponseStarted(ttfbMillis)
                }

                override fun onTransferComplete(bytesSent: Long, bytesReceived: Long) {
                    metrics.recordTransferComplete(bytesSent, bytesReceived)
                }
            }
        )
        call.inFlight = transportCall
        if (call.isCanceled) transportCall.cancel()

        transportCall.enqueue(object : Callback {
            override fun onResponse(call: Call, response: Response) {
                result.set(response)
                done.countDown()
            }

            override fun onFailure(call: Call, e: IOException) {
                failure.set(e)
                done.countDown()
            }
        })

        // The transport owes exactly one terminal callback, including after a cancel, but an
        // unbounded wait here would strand the caller for good on the day it does not deliver.
        val wait = (deadlineAt - System.currentTimeMillis()).coerceAtLeast(0) + TERMINAL_CALLBACK_GRACE_MS
        if (!done.await(wait, TimeUnit.MILLISECONDS)) {
            transportCall.cancel()
            throw ApifierException.CallTimeout(timeoutMs)
        }
        // inFlight stays set: the body is still streaming through this call, so a cancel after
        // the headers arrive has to reach it.

        failure.get()?.let { throw it }
        val response = checkNotNull(result.get())
        saveCookies(request.uri, response.headers)
        return response
    }

    /** Runs for every response the transport hands over, including ones the retry loop discards. */
    private fun saveCookies(uri: Uri, headers: Headers) {
        val jar = cookieJar ?: return
        val psl = publicSuffixList ?: return
        val cookies = Cookie.parseAll(uri, headers, psl)
        if (cookies.isNotEmpty()) jar.saveFromResponse(uri, cookies)
    }

    private fun withProgress(request: Request, response: Response): Response {
        val listener = request.tag(ProgressListener::class.java) ?: return response
        return response.newBuilder().body(ProgressBody(response.body, listener)).build()
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
    private fun backoffSleep(delayMs: Long, call: PipelineCall, timeoutMs: Long) {
        var remaining = delayMs
        while (remaining > 0) {
            surrenderIfDone(call, timeoutMs)
            val slice = remaining.coerceAtMost(BACKOFF_SLICE_MS)
            try {
                Thread.sleep(slice)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                // An interrupted worker thread ends this call. Recording it on the call keeps a
                // pool shutdown from charging every in-flight host with a failure.
                call.cancel()
                throw ApifierException.Cancelled()
            }
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
        val perRequest = if (willRetry) null else options.observer
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
     * breaker, a surrender ahead of an attempt, or a cancel/timeout landing in backoff between
     * attempts. Nothing reached the transport, so there is nothing to wait on; the metrics are zero.
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
            options.observer
        )
    }

    private fun errorCodeOf(e: IOException): ErrorCode = (e as? ApifierException)?.errorCode ?: ErrorCode.OTHER

    private companion object {
        val IDEMPOTENT_METHODS = setOf("GET", "HEAD")
        const val BACKOFF_SLICE_MS = 50L
        const val TRUST_VERDICT_WAIT_MS = 2_000L
        const val TERMINAL_CALLBACK_GRACE_MS = 250L
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

    private var bounded: BufferedSource? = null

    override fun contentType(): MediaType? = body.contentType()

    override fun contentLength(): Long = body.contentLength()

    override fun source(): BufferedSource =
        bounded ?: bounding(body.source()).buffer().also { bounded = it }

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

/** Reports read progress as the consumer drains [body]. */
private class ProgressBody(
    private val body: ResponseBody,
    private val listener: ProgressListener
) : ResponseBody() {

    private var counted: BufferedSource? = null
    private val totalRead = AtomicLong(0L)
    private val lastReported = AtomicLong(-1L)
    private val doneReported = AtomicBoolean(false)

    override fun contentType(): MediaType? = body.contentType()

    override fun contentLength(): Long = body.contentLength()

    override fun source(): BufferedSource =
        counted ?: counting(body.source()).buffer().also { counted = it }

    private fun counting(source: Source): Source = object : ForwardingSource(source) {
        override fun read(sink: Buffer, byteCount: Long): Long {
            val bytesRead = super.read(sink, byteCount)
            if (bytesRead == -1L) {
                // EOF often lands on a byte total the previous read already reported, so the
                // dedup guard below would swallow the done signal.
                if (!doneReported.getAndSet(true)) {
                    listener.update(totalRead.get(), body.contentLength(), true)
                }
                return bytesRead
            }
            val current = totalRead.addAndGet(bytesRead)
            val last = lastReported.get()
            if (current != last && lastReported.compareAndSet(last, current)) {
                listener.update(current, body.contentLength(), false)
            }
            return bytesRead
        }
    }
}
