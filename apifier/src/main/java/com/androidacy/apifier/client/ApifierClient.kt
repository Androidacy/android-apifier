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
import android.net.Network
import android.os.Looper
import android.util.Log
import com.androidacy.apifier.dns.ProtectedDomainCheck
import com.androidacy.apifier.dns.TrustStatus
import com.androidacy.apifier.http.ApifierException
import com.androidacy.apifier.http.Call
import com.androidacy.apifier.http.Callback
import com.androidacy.apifier.http.MediaType.Companion.toMediaTypeOrNull
import com.androidacy.apifier.http.MultipartBody
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.http.RequestBody.Companion.asRequestBody
import com.androidacy.apifier.http.RequestBody.Companion.toRequestBody
import com.androidacy.apifier.http.Response
import com.androidacy.apifier.observe.Observation
import com.androidacy.apifier.observe.RequestEvent
import com.androidacy.apifier.observe.RequestObserver
import com.androidacy.apifier.progress.Progress
import com.androidacy.apifier.security.PublicSuffixList
import com.androidacy.apifier.security.SecureCookieJar
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import org.chromium.net.CronetEngine
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Tag marker to skip automatic retries on a per-request basis. */
object NoRetry

/** Marks this request to skip automatic retries. */
fun Request.Builder.noRetry(): Request.Builder = tag(NoRetry::class.java, NoRetry)

/**
 * The engine side of the client as one unit: the calls it starts, the labels it reports, and the
 * teardown [ApifierClient.close] orders its other steps against. An interface because neither
 * [CronetTransport] nor `CronetEngine` can be substituted in a test.
 */
internal interface ClientEngine : AttemptTransport {

    /** Label for the engine serving these calls, reported with every observation event. */
    val provider: String

    val providerReport: Map<String, String>

    /** Stops the engine and the pool its callbacks run on. In-flight calls are already cancelled. */
    fun shutdown()
}

internal class CronetClientEngine(
    private val engine: CronetEngine,
    override val providerReport: Map<String, String>,
    readTimeoutMs: Long
) : ClientEngine {

    private val transport = CronetTransport(engine, readTimeoutMs)

    override val provider: String = transport.provider

    override fun newCall(request: Request, listener: TransportListener?): AttemptCall =
        transport.newCall(request, listener)

    /**
     * The engine goes first: a request still winding down reaches its terminal state on the
     * callback pool, so stopping that pool first would strand it and leave the engine refusing
     * to shut down for as long as it stayed active.
     */
    override fun shutdown() {
        val deadline = System.currentTimeMillis() + ENGINE_SHUTDOWN_WAIT_MS
        while (true) {
            // Cronet answers an active request with IllegalStateException. A straggler is worth
            // a short wait and never worth throwing out of close().
            if (runCatching { engine.shutdown() }.isSuccess) break
            if (System.currentTimeMillis() >= deadline) break
            try {
                Thread.sleep(ENGINE_SHUTDOWN_POLL_MS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
        }
        transport.shutdown()
    }

    companion object {
        private const val ENGINE_SHUTDOWN_WAIT_MS = 2_000L
        private const val ENGINE_SHUTDOWN_POLL_MS = 25L

        /** Runs the provider ladder, which blocks and belongs off the main thread. */
        fun build(context: Context, config: NetworkConfig): CronetClientEngine {
            val builder = HttpClientBuilder(context, config)
            val engine = builder.build()
            return CronetClientEngine(
                engine,
                builder.providerReport,
                config.timeouts.read.inWholeMilliseconds
            )
        }
    }
}

/**
 * HTTP client backed by Cronet.
 *
 * Every call runs through one pipeline: call timeout, protected-domain gate, circuit breaker,
 * retry, headers, cookies, progress. [call] is the entry point and the request-shaped helpers
 * are sugar over it.
 *
 * Construction blocks. Selecting a Cronet provider reaches Google Play services, which can wait
 * on a Dynamite download, so build the client on a background thread.
 *
 * The client owns an engine, its thread pools and, when protected domains are configured, a
 * network callback. [close] releases all of them and the instance is unusable afterwards.
 *
 * @param context Android context for Cronet provider initialization
 * @param config network and transport configuration
 */
class ApifierClient internal constructor(
    context: Context,
    config: NetworkConfig,
    private val engine: ClientEngine
) : Closeable {

    constructor(context: Context, config: NetworkConfig) :
        this(context, config, CronetClientEngine.build(context, config))

    private val appContext = context.applicationContext

    private val workers: ExecutorService = Executors.newCachedThreadPool { runnable ->
        Thread(runnable, "Apifier-Call").apply { isDaemon = true }
    }

    private val scheduler: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "Apifier-Timeout").apply { isDaemon = true }
        }

    // DNS probes are blocking and unrelated to any one call, so they get their own thread rather
    // than occupying a worker that a call is waiting for.
    private val trustExecutor: ExecutorService? =
        if (config.protectedDomains.isEmpty()) {
            null
        } else {
            Executors.newSingleThreadExecutor { runnable ->
                Thread(runnable, "Apifier-Trust").apply { isDaemon = true }
            }
        }

    private val trustCheck: ProtectedDomainCheck? = trustExecutor?.let { executor ->
        ProtectedDomainCheck.production(appContext, config.protectedDomains, executor).apply {
            setEnforceProtectedDomains(config.enforceProtectedDomains)
            start()
        }
    }

    private val connectivity = appContext.getSystemService(ConnectivityManager::class.java)

    private val networkCallback: ConnectivityManager.NetworkCallback? =
        trustCheck?.let { check ->
            connectivity?.let { manager ->
                object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) = check.onNetworkChanged()
                }.also(manager::registerDefaultNetworkCallback)
            }
        }

    private val observation = Observation()

    private val pipeline: Pipeline = run {
        val cookieJar = config.cookieStorage?.let(::SecureCookieJar)
        Pipeline(
            engine::newCall,
            config,
            cookieJar,
            if (cookieJar == null) null else PublicSuffixList.load(appContext),
            trustCheck,
            BreakerRegistry(config.circuitBreakerConfig),
            scheduler,
            engine.provider,
            observation
        )
    }

    private val inFlight = ConcurrentHashMap.newKeySet<ClientCall>()

    private val closed = AtomicBoolean(false)

    private val inCallback: ThreadLocal<Boolean> = ThreadLocal.withInitial { false }

    /**
     * Provider selection outcome in ladder order. Keys are `name:version`, values are the
     * `HttpClientBuilder.PROVIDER_*` statuses.
     */
    val providerReport: Map<String, String> get() = engine.providerReport

    /**
     * Prepares [request] for execution. The returned [Call] runs the whole pipeline once, on the
     * client's worker pool for [Call.enqueue] and on the calling thread for [Call.execute].
     *
     * A request marked with [noRetry] is limited to one attempt whatever [options] asks for.
     *
     * @throws IllegalStateException the client is closed.
     */
    fun call(request: Request, options: CallOptions = CallOptions()): Call {
        check(!closed.get()) { CLOSED_MESSAGE }
        val effective =
            if (request.tag(NoRetry::class.java) == null) options else options.copy(maxAttempts = 1)
        return ClientCall(request, effective)
    }

    /** Enqueues an async GET. Returns the [Call] for cancellation. */
    fun get(url: String, callback: Callback): Call =
        enqueue(Request.Builder().url(url).get().build(), callback)

    /** Enqueues an async POST. [contentType] defaults to JSON. Returns the [Call] for cancellation. */
    fun post(url: String, body: String, contentType: String = "application/json", callback: Callback): Call {
        val requestBody = body.toRequestBody(contentType.toMediaTypeOrNull())
        return enqueue(Request.Builder().url(url).post(requestBody).build(), callback)
    }

    /** Enqueues an async DELETE. Returns the [Call] for cancellation. */
    fun delete(url: String, callback: Callback): Call =
        enqueue(Request.Builder().url(url).delete().build(), callback)

    /** Enqueues an async HEAD. Returns the [Call] for cancellation. */
    fun head(url: String, callback: Callback): Call =
        enqueue(Request.Builder().url(url).head().build(), callback)

    /** GET with progress tracking. Build [progress] with `extraBufferCapacity > 0`; see [CallOptions.progress]. */
    fun download(url: String, progress: MutableSharedFlow<Progress>, callback: Callback): Call {
        val request = Request.Builder().url(url).get().build()
        return enqueue(request, callback, CallOptions(progress = progress))
    }

    /** Multipart file upload. [fileNames] are form-data field names matching [files] by index. */
    fun upload(
        url: String,
        files: List<File>,
        fileNames: List<String>,
        progress: MutableSharedFlow<Progress>? = null,
        callback: Callback
    ): Call {
        require(files.isNotEmpty()) { "Files list cannot be empty" }
        require(files.size == fileNames.size) { "Files and fileNames must have the same size" }

        val requestBody = MultipartBody.Builder()
            .setType(MultipartBody.FORM)
            .apply {
                files.forEachIndexed { index, file ->
                    require(file.exists()) { "File does not exist: ${file.absolutePath}" }
                    addFormDataPart(
                        fileNames[index],
                        file.name,
                        file.asRequestBody("application/octet-stream".toMediaTypeOrNull())
                    )
                }
            }
            .build()

        val request = Request.Builder().url(url).post(requestBody).build()
        return enqueue(request, callback, CallOptions(progress = progress))
    }

    /** Every [RequestEvent] this client's calls report, across every request. */
    val events: SharedFlow<RequestEvent> get() = observation.events

    /** Registers [observer] for every call this client runs. Events arrive off the network thread. */
    @Suppress("DEPRECATION")
    @Deprecated("RequestEvent carries no call identity, but a global observer never needed one.", ReplaceWith("events"))
    fun addObserver(observer: RequestObserver) {
        observation.addObserver(observer)
    }

    @Suppress("DEPRECATION")
    @Deprecated("RequestEvent carries no call identity, but a global observer never needed one.", ReplaceWith("events"))
    fun removeObserver(observer: RequestObserver) {
        observation.removeObserver(observer)
    }

    /**
     * Turns blocking on or off for the configured protected domains. Verdicts keep computing
     * either way and stay readable through [protectedDomainStatus].
     */
    fun setEnforceProtectedDomains(enforce: Boolean) {
        trustCheck?.setEnforceProtectedDomains(enforce)
    }

    /** Latest verdict for [host], or `UNKNOWN` when it is not protected or has no verdict yet. */
    fun protectedDomainStatus(host: String): TrustStatus =
        trustCheck?.status(host) ?: TrustStatus.UNKNOWN

    /**
     * Releases the engine, the pools and the network callback. Idempotent.
     *
     * In-flight calls are cancelled and awaited first, because the engine refuses to shut down
     * while a request is active. Observation stops last so events from those cancellations are
     * delivered before this returns.
     *
     * @throws IllegalStateException called from a callback this client is running. That thread
     * is one of the calls close has to wait for, so it would drain against itself, be interrupted
     * out of the drain, and lose the pending events.
     */
    override fun close() {
        check(!inCallback.get()) { "close() must not be called from a callback of this client" }
        if (!closed.compareAndSet(false, true)) return

        // One failing step must not take the rest of the teardown with it.
        teardown {
            networkCallback?.let { callback -> connectivity?.unregisterNetworkCallback(callback) }
        }
        teardown { inFlight.forEach { it.cancel() } }
        // Ahead of the drain, since this releases a call parked on a verdict that is never
        // coming; waiting for it would spend the whole trust budget inside close.
        teardown { trustCheck?.shutdown() }
        teardown { trustExecutor?.shutdownNow() }
        teardown { drainCalls() }
        // A response body the consumer never closed still holds its call-budget task, so an
        // orderly shutdown here would wait out the whole budget for nothing.
        teardown { scheduler.shutdownNow() }
        teardown { engine.shutdown() }
        teardown { observation.close() }
    }

    private fun teardown(step: () -> Unit) {
        runCatching(step)
    }

    private fun drainCalls() {
        workers.shutdown()
        val deadline = System.currentTimeMillis() + DRAIN_TIMEOUT_MS
        try {
            // awaitTermination alone would miss a call running on a caller's thread through
            // execute(), which is in flight without occupying a worker.
            while (inFlight.isNotEmpty() && System.currentTimeMillis() < deadline) {
                Thread.sleep(DRAIN_POLL_MS)
            }
            val remaining = (deadline - System.currentTimeMillis()).coerceAtLeast(0)
            if (!workers.awaitTermination(remaining, TimeUnit.MILLISECONDS)) workers.shutdownNow()
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            workers.shutdownNow()
        }
    }

    private fun enqueue(request: Request, callback: Callback, options: CallOptions = CallOptions()): Call =
        call(request, options).also { it.enqueue(callback) }

    /**
     * One logical call: a pipeline run the client can cancel and account for while it is in
     * flight. A call counts as in flight until the pipeline fails or its response body ends,
     * which is later than the consumer callback returns and is what [close] has to reach: the
     * engine stays active for as long as the body is streaming.
     */
    private inner class ClientCall(
        private val request: Request,
        private val options: CallOptions
    ) : Call {

        private val state = PipelineCall()
        private val started = AtomicBoolean(false)

        init {
            state.onBodyFinished = { inFlight.remove(this) }
        }

        override fun request(): Request = request

        override fun enqueue(callback: Callback) {
            begin()
            try {
                workers.execute { run(callback) }
            } catch (e: RejectedExecutionException) {
                inFlight.remove(this)
                callback.onFailure(this, ApifierException.Cancelled())
            }
        }

        @Deprecated("Blocking bridge over the async path; prefer enqueue.")
        override fun execute(): Response {
            begin()
            if (Looper.getMainLooper().isCurrentThread) {
                Log.w(TAG, "HTTP request on main thread; this will block the UI and may cause ANR")
            }
            try {
                return pipeline.executeBlocking(request, options, state)
            } catch (e: Throwable) {
                inFlight.remove(this)
                throw asDeclaredFailure(e)
            }
        }

        override fun cancel() = state.cancel()

        override fun isCanceled(): Boolean = state.isCanceled

        private fun begin() {
            check(started.compareAndSet(false, true)) { "Call already enqueued" }
            check(!closed.get()) { CLOSED_MESSAGE }
            inFlight.add(this)
        }

        private fun run(callback: Callback) {
            val response = try {
                pipeline.executeBlocking(request, options, state)
            } catch (e: Throwable) {
                inFlight.remove(this)
                // The consumer is owed exactly one terminal callback. An interrupt during a
                // shutdown, or any other non-IO failure, must not leave it waiting forever.
                dispatch { callback.onFailure(this, asDeclaredFailure(e)) }
                return
            }
            dispatch { callback.onResponse(this, response) }
        }

        /** Marks the thread as the client's own, so [close] can refuse the one caller it cannot serve. */
        private fun dispatch(delivery: () -> Unit) {
            inCallback.set(true)
            try {
                delivery()
            } finally {
                inCallback.set(false)
            }
        }
    }

    companion object {
        private const val TAG = "ApifierClient"
        private const val DRAIN_TIMEOUT_MS = 5_000L
        private const val DRAIN_POLL_MS = 10L
        private const val CLOSED_MESSAGE = "client is closed"

        private fun asDeclaredFailure(e: Throwable): IOException =
            e as? ApifierException ?: ApifierException.Unexpected(e)

        operator fun invoke(context: Context, block: NetworkConfigBuilder.() -> Unit): ApifierClient {
            val config = NetworkConfigBuilder().apply(block).build()
            return ApifierClient(context, config)
        }
    }
}
