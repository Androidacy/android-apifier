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
@file:Suppress("DEPRECATION")

package com.androidacy.apifier.client

import android.content.Context
import android.os.Looper
import android.util.Log
import com.androidacy.apifier.patterns.BackoffConfig
import com.androidacy.apifier.patterns.CircuitBreaker
import com.androidacy.apifier.patterns.ExponentialBackoff
import com.androidacy.apifier.progress.ProgressListener
import com.androidacy.apifier.progress.ProgressResponseBody
import com.androidacy.apifier.security.SecureCookieJar
import com.google.android.gms.net.CronetProviderInstaller
import com.google.android.gms.tasks.Tasks
import okhttp3.Call
import okhttp3.ConnectionPool
import okhttp3.ConnectionSpec
import okhttp3.Cookie
import okhttp3.Dispatcher
import okhttp3.OkHttpClient
import org.chromium.net.CronetEngine
import org.chromium.net.CronetProvider
import org.chromium.net.DnsOptions
import org.chromium.net.ExperimentalCronetEngine
import org.chromium.net.QuicOptions
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Assembles an [OkHttpClient] with Cronet transport, DoH, retries, and cookie support. */
class HttpClientBuilder(
    private val context: Context,
    private val config: NetworkConfig
) {
    companion object {
        private const val TAG = "HttpClientBuilder"
        private val IDEMPOTENT_METHODS = setOf("GET", "HEAD")
        private const val BACKOFF_SLICE_MS = 50L

        const val PROVIDER_IN_USE = "IN_USE"
        const val PROVIDER_TOO_OLD = "TOO_OLD"
        const val PROVIDER_INELIGIBLE_PLAT = "INELIGIBLE_PLAT"
        const val PROVIDER_FAILED = "FAILED"
        const val PROVIDER_NOT_PRESENT = "NOT_PRESENT"

        private const val GMS_PROVIDER_NAME = "Google-Play-Services-Cronet-Provider"
        private const val JAVA_PROVIDER_CLASS = "org.chromium.net.impl.JavaCronetProvider"

        /** Lightweight freshness guard, not a compatibility floor. */
        private const val MIN_ENGINE_VERSION = "141.0.7340.3"

        private fun isAtLeast(version: String, minimum: String): Boolean {
            val actual = version.split('.')
            val floor = minimum.split('.')
            for (i in 0 until maxOf(actual.size, floor.size)) {
                val a = actual.getOrNull(i)?.toIntOrNull() ?: 0
                val f = floor.getOrNull(i)?.toIntOrNull() ?: 0
                if (a != f) return a > f
            }
            return true
        }
    }

    /**
     * True once [build] has installed DoH-resolved HostResolverRules into the engine.
     * False means DoH produced nothing and the engine fell back to system DNS — e.g.
     * construction happened on the main thread (blocking I/O skipped) or the network
     * was unavailable. Read-only to consumers.
     */
    var dohActive: Boolean = false
        private set

    /**
     * Provider selection outcome in ladder order. Keys are `name:version`, or the bare name
     * when the version could not be read. Empty until [build] runs.
     */
    var providerReport: Map<String, String> = emptyMap()
        private set

    private val breakers = ConcurrentHashMap<String, CircuitBreaker>()

    fun build(): OkHttpClient {
        if (Looper.getMainLooper().isCurrentThread) {
            Log.d(TAG, "Constructed on the main thread; DoH/provider I/O may be skipped")
        }

        val dohConfig = config.cronetConfig.dohConfig
        val resolver = if (dohConfig.enabled) DohResolver(dohConfig) else null

        // Resolve configured domains via DoH before building the engine so
        // HostResolverRules are baked in from the start. Parallelized internally.
        @Suppress("DEPRECATION")
        val domains = (dohConfig.dohDomains + dohConfig.preResolveDomains).distinct()
        if (resolver != null && domains.isNotEmpty()) {
            resolver.preResolve(domains)
            // Happy Eyeballs: race IPv6 vs IPv4 per domain to pick the best
            // reachable address. HostResolverRules only accept a single IP and
            // bypass Cronet's own Happy Eyeballs, so we must do our own.
            resolver.raceResolvedAddresses()
        }

        val engine = buildEngine(resolver)

        // Warn whenever DoH was expected to produce host rules but did not — for any
        // reason (network down, all providers failed, main-thread I/O skipped). The
        // client still works via system DNS, but callers relying on DoH should know.
        if (resolver != null && domains.isNotEmpty() && !dohActive) {
            Log.w(TAG, "DoH resolution produced no host rules; falling back to system DNS")
        }

        val builder = OkHttpClient.Builder().apply {
            connectTimeout(config.timeouts.connect.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            readTimeout(config.timeouts.read.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            writeTimeout(config.timeouts.write.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            callTimeout(config.timeouts.call.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            fastFallback(true)
            connectionSpecs(listOf(ConnectionSpec.MODERN_TLS))
            dispatcher(createDispatcher())
            connectionPool(createConnectionPool())
        }

        val cookieJar = config.cookieStorage?.let { SecureCookieJar(it) }
        builder.addInterceptor(createMainInterceptor(cookieJar))

        builder.addInterceptor(CronetCallInterceptor(engine, config.timeouts.read.inWholeMilliseconds))

        return builder.build()
    }

    private fun createDispatcher(): Dispatcher {
        val numCpus = Runtime.getRuntime().availableProcessors()
        val threadCount = AtomicInteger(0)
        val executor = Executors.newFixedThreadPool((numCpus / 2).coerceAtLeast(2)) { runnable ->
            Thread(runnable, "Http-Worker-${threadCount.incrementAndGet()}").apply {
                isDaemon = true
                priority = Thread.NORM_PRIORITY - 1
            }
        }
        return Dispatcher(executor).apply {
            maxRequests = numCpus * 3
            maxRequestsPerHost = 3
        }
    }

    private fun createConnectionPool() = ConnectionPool(
        config.connectionPool.maxIdleConnections,
        config.connectionPool.keepAliveDuration.inWholeMilliseconds,
        TimeUnit.MILLISECONDS
    )

    private fun createMainInterceptor(cookieJar: SecureCookieJar?) = okhttp3.Interceptor { chain ->
        val cbConfig = config.circuitBreakerConfig
        val breaker = if (cbConfig.enabled) {
            breakers.getOrPut(chain.request().url.host) {
                CircuitBreaker(cbConfig.failureThreshold, cbConfig.resetTimeoutMs)
            }
        } else null

        if (breaker != null && !breaker.checkState()) {
            throw IOException("Circuit breaker open for ${chain.request().url.host}")
        }

        var attempt = 0
        var lastException: IOException? = null
        // Align the backoff's own attempt ceiling with the retry loop so its -1
        // "exceeded" sentinel is never reached from inside the loop.
        val backoff = ExponentialBackoff(BackoffConfig(maxAttempts = config.retryConfig.maxAttempts))
        val maxAttempts = if (chain.request().tag(NoRetry::class.java) != null) 1
            else config.retryConfig.maxAttempts

        while (attempt < maxAttempts) {
            if (chain.call().isCanceled()) throw IOException("Canceled")

            val originalRequest = chain.request()
            val req = originalRequest.newBuilder().apply {
                config.headers.forEach { (name, value) -> header(name, value) }
                config.dynamicHeaders.forEach { (name, provider) -> header(name, provider()) }

                cookieJar?.loadForRequest(originalRequest.url)?.takeIf { it.isNotEmpty() }?.let { cookies ->
                    header("Cookie", cookies.joinToString("; ") { "${it.name}=${it.value}" })
                }
            }.build()

            try {
                val resp = chain.proceed(req)
                val isIdempotent = req.method in IDEMPOTENT_METHODS

                if (resp.code >= 500 && attempt < maxAttempts - 1 &&
                    config.retryConfig.retryOn5xx &&
                    (!config.retryConfig.retryIdempotentOnly || isIdempotent)
                ) {
                    resp.close()
                    val delayMs = backoff.calculateDelay(attempt)
                    attempt++
                    backoffSleep(delayMs, chain.call())
                    continue
                }

                // Record one outcome per call: a 5xx returned to the caller is a
                // server failure, anything else means the host is responding.
                if (resp.code >= 500) breaker?.recordFailure() else breaker?.recordSuccess()

                cookieJar?.let { jar ->
                    resp.headers("Set-Cookie")
                        .mapNotNull { Cookie.parse(req.url, it) }
                        .takeIf { it.isNotEmpty() }
                        ?.let { jar.saveFromResponse(req.url, it) }
                }

                return@Interceptor req.tag(ProgressListener::class.java)?.let { listener ->
                    resp.body?.let { body ->
                        resp.newBuilder().body(ProgressResponseBody(body, listener)).build()
                    } ?: resp
                } ?: resp

            } catch (e: IOException) {
                lastException = e
                val isIdempotent = req.method in IDEMPOTENT_METHODS
                if (attempt < maxAttempts - 1 &&
                    (!config.retryConfig.retryIdempotentOnly || isIdempotent)
                ) {
                    val delayMs = backoff.calculateDelay(attempt)
                    attempt++
                    backoffSleep(delayMs, chain.call())
                    continue
                }
                breaker?.recordFailure()
                throw e
            }
        }

        breaker?.recordFailure()
        throw lastException ?: IOException("Request failed")
    }

    /**
     * Sleep for [delayMs], surrendering promptly if the call is canceled. The retry loop
     * would otherwise burn the full backoff (and every remaining attempt) after cancellation.
     */
    private fun backoffSleep(delayMs: Long, call: Call) {
        if (delayMs <= 0) return
        var remaining = delayMs
        while (remaining > 0) {
            if (call.isCanceled()) throw IOException("Canceled")
            val slice = remaining.coerceAtMost(BACKOFF_SLICE_MS)
            try {
                Thread.sleep(slice)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw IOException("Interrupted during retry backoff", e)
            }
            remaining -= slice
        }
    }

    private fun consider(
        providers: List<CronetProvider>,
        name: String,
        absentStatus: String,
        minVersion: String?,
        report: MutableMap<String, String>
    ): CronetProvider? {
        val provider = providers.firstOrNull { it.name == name }
        if (provider == null || !provider.isEnabled) {
            report[name] = absentStatus
            return null
        }
        val version = runCatching { provider.version }.getOrNull()
        if (version == null) {
            report[name] = PROVIDER_FAILED
            return null
        }
        val key = "$name:$version"
        if (minVersion != null && !isAtLeast(version, minVersion)) {
            report[key] = PROVIDER_TOO_OLD
            return null
        }
        report[key] = PROVIDER_IN_USE
        return provider
    }

    private fun selectProvider(report: MutableMap<String, String>): CronetProvider {
        val installed = CronetProvider.getAllProviders(context)
        consider(
            installed, CronetProvider.PROVIDER_NAME_HTTPENGINE_NATIVE,
            PROVIDER_INELIGIBLE_PLAT, MIN_ENGINE_VERSION, report
        )?.let { return it }

        // Deferred past the platform rung: GMS reports disabled until this completes, and it
        // can block on a Dynamite download.
        val withGms = try {
            Tasks.await(CronetProviderInstaller.installProvider(context))
            CronetProvider.getAllProviders(context)
        } catch (e: Exception) {
            installed
        }

        consider(withGms, GMS_PROVIDER_NAME, PROVIDER_NOT_PRESENT, MIN_ENGINE_VERSION, report)
            ?.let { return it }
        consider(withGms, CronetProvider.PROVIDER_NAME_APP_PACKAGED, PROVIDER_NOT_PRESENT, null, report)
            ?.let { return it }
        consider(withGms, CronetProvider.PROVIDER_NAME_FALLBACK, PROVIDER_NOT_PRESENT, null, report)
            ?.let { return it }

        val reflective = runCatching {
            Class.forName(JAVA_PROVIDER_CLASS)
                .getConstructor(Context::class.java)
                .newInstance(context) as CronetProvider
        }.getOrNull() ?: throw IllegalStateException("No Cronet provider available")

        val version = runCatching { reflective.version }.getOrNull()
        report[if (version == null) reflective.name else "${reflective.name}:$version"] = PROVIDER_IN_USE
        return reflective
    }

    @Suppress("UnsafeOptInUsageError", "DEPRECATION")
    private fun buildEngine(resolver: DohResolver?): CronetEngine {
        val report = LinkedHashMap<String, String>()
        val provider = selectProvider(report)
        providerReport = report

        val builder = provider.createBuilder().apply {
            enableBrotli(config.cronetConfig.enableBrotli)
            enableHttp2(config.cronetConfig.enableHttp2)
            enableQuic(config.cronetConfig.enableQuic)

            if (config.cronetConfig.enableQuic) {
                setQuicOptions(
                    QuicOptions.builder()
                        .retryWithoutAltSvcOnQuicErrors(true)
                        .enableTlsZeroRtt(true)
                        .setInMemoryServerConfigsCacheSize(8192)
                        .build()
                )
                config.cronetConfig.quicHints.forEach { (host, port, alternatePort) -> addQuicHint(host, port, alternatePort) }
            }

            if (config.cronetConfig.enableDnsOverHttps) {
                setDnsOptions(
                    DnsOptions.builder()
                        .preestablishConnectionsToStaleDnsResults(config.cronetConfig.enableStaleDns)
                        .enableStaleDns(config.cronetConfig.enableStaleDns)
                        .useBuiltInDnsResolver(true)
                        .persistHostCache(true)
                        .build()
                )
            }

            config.cronetConfig.cacheDirectory?.let { dir ->
                if (!dir.exists() && !dir.mkdirs()) {
                    throw IOException("Failed to create cronet cache directory")
                }
                setStoragePath(dir.absolutePath)
                enableHttpCache(CronetEngine.Builder.HTTP_CACHE_DISK, config.cronetConfig.cacheSizeBytes)
            }

            enablePublicKeyPinningBypassForLocalTrustAnchors(false)
        }

        // Bake pre-resolved HostResolverRules into the engine
        val hostRules = resolver?.buildHostResolverRules()
        dohActive = hostRules != null
        if (hostRules != null) {
            val experimentalJson = JSONObject().apply {
                put("HostResolverRules", JSONObject().put("host_resolver_rules", hostRules))
                put("AsyncDNS", JSONObject().put("enable", true))
            }.toString()
            applyExperimentalOptions(builder, experimentalJson)
        }

        return builder.build()
    }

    private fun applyExperimentalOptions(builder: CronetEngine.Builder, json: String) {
        if (builder is ExperimentalCronetEngine.Builder) {
            builder.setExperimentalOptions(json)
            return
        }

        // Reflection fallback for provider-wrapped builders
        try {
            val delegateField = builder.javaClass.getDeclaredField("mBuilderDelegate")
            delegateField.isAccessible = true
            val delegate = delegateField.get(builder)
            val setMethod = delegate.javaClass.getMethod("setExperimentalOptions", String::class.java)
            setMethod.invoke(delegate, json)
        } catch (e: Exception) {
            Log.w(TAG, "Could not set experimental options (HostResolverRules): ${e.message}")
        }
    }
}
