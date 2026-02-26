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
import android.util.Log
import com.androidacy.apifier.patterns.ExponentialBackoff
import com.androidacy.apifier.progress.ProgressListener
import com.androidacy.apifier.progress.ProgressResponseBody
import com.androidacy.apifier.security.SecureCookieJar
import com.google.android.gms.net.CronetProviderInstaller
import com.google.android.gms.tasks.Tasks
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
        private const val SHUTDOWN_MAX_ATTEMPTS = 5
        private const val SHUTDOWN_RETRY_DELAY_MS = 200L
        private const val OLD_ENGINE_CLEANUP_DELAY_S = 10L
    }

    fun build(): OkHttpClient {
        val dohConfig = config.cronetConfig.dohConfig
        val resolver = if (dohConfig.enabled) DohResolver(dohConfig) else null

        val managedEngine = ManagedCronetEngine(context, config, resolver)

        // Pre-resolve configured domains off the calling thread
        if (resolver != null && dohConfig.preResolveDomains.isNotEmpty()) {
            Thread({ resolver.preResolve(dohConfig.preResolveDomains) }, "DoH-PreResolve")
                .apply { isDaemon = true }
                .start()
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

        builder.addInterceptor(CronetCallInterceptor(managedEngine, resolver))

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
        config.connectionPool.keepAliveDuration.inWholeMinutes,
        TimeUnit.MINUTES
    )

    private fun createMainInterceptor(cookieJar: SecureCookieJar?) = okhttp3.Interceptor { chain ->
        var attempt = 0
        var lastException: IOException? = null
        val backoff = ExponentialBackoff()
        val maxAttempts = if (chain.request().tag(NoRetry::class.java) != null) 1
            else config.retryConfig.maxAttempts

        while (attempt < maxAttempts) {
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
                    attempt++
                    val delayMs = backoff.calculateDelay(attempt)
                    if (delayMs > 0) {
                        Thread.sleep(delayMs)
                    }
                    continue
                }

                cookieJar?.let { jar ->
                    (resp.headers("Set-Cookie") + resp.headers("set-cookie") + resp.headers("set-cookie2"))
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
                    attempt++
                    val delayMs = backoff.calculateDelay(attempt)
                    if (delayMs > 0) {
                        Thread.sleep(delayMs)
                    }
                    continue
                }
                throw e
            }
        }

        throw lastException ?: IOException("Request failed")
    }

    internal class ManagedCronetEngine(
        private val context: Context,
        private val config: NetworkConfig,
        private val resolver: DohResolver?
    ) {
        @Volatile
        var currentEngine: CronetEngine = buildEngine()
            private set

        private val rebuildLock = Any()
        private val shutdownExecutor = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "Cronet-Shutdown").apply { isDaemon = true }
        }

        fun rebuildIfDirty(): CronetEngine {
            if (resolver == null) return currentEngine
            synchronized(rebuildLock) {
                if (!resolver.consumeRulesDirty()) return currentEngine
                val oldEngine = currentEngine

                // Try to shut down old engine (releases disk cache lock).
                // Retry briefly — we're on an IO thread, not main.
                var shutdownOk = false
                for (attempt in 0 until SHUTDOWN_MAX_ATTEMPTS) {
                    try {
                        oldEngine.shutdown()
                        shutdownOk = true
                        break
                    } catch (e: Exception) {
                        if (attempt < SHUTDOWN_MAX_ATTEMPTS - 1) Thread.sleep(SHUTDOWN_RETRY_DELAY_MS)
                    }
                }

                if (shutdownOk) {
                    currentEngine = buildEngine(useDiskCache = true)
                } else {
                    // Active requests prevent shutdown — rebuild with in-memory cache
                    // to avoid disk lock contention while still applying new DNS rules
                    Log.w(TAG, "Old engine busy, rebuilding with in-memory cache to avoid DNS leak")
                    currentEngine = buildEngine(useDiskCache = false)
                    // Clean up old engine once its requests drain
                    shutdownExecutor.schedule({
                        try { oldEngine.shutdown() } catch (_: Exception) {}
                    }, OLD_ENGINE_CLEANUP_DELAY_S, TimeUnit.SECONDS)
                }
                return currentEngine
            }
        }

        @Suppress("UnsafeOptInUsageError", "DEPRECATION")
        private fun buildEngine(useDiskCache: Boolean = true): CronetEngine {
            val providers = try {
                Tasks.await(CronetProviderInstaller.installProvider(context))
                CronetProvider.getAllProviders(context)
            } catch (e: Exception) {
                CronetProvider.getAllProviders(context)
            }

            val provider = sequenceOf(
                providers.find { it.isEnabled && it.name == "Google-Play-Services-Cronet-Provider" },
                providers.find { it.isEnabled && it.name !in setOf("Google-Play-Services-Cronet-Provider", "Java-Cronet-Provider") },
                providers.find { it.isEnabled && it.name == "Java-Cronet-Provider" },
                runCatching {
                    val cls = Class.forName("org.chromium.net.impl.JavaCronetProvider")
                    cls.getConstructor(Context::class.java).newInstance(context) as CronetProvider
                }.getOrNull()
            ).filterNotNull().firstOrNull() ?: throw IllegalStateException("No Cronet provider available")

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
                    config.cronetConfig.quicHints.forEach { (host, port) -> addQuicHint(host, 443, port) }
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

                if (useDiskCache) {
                    config.cronetConfig.cacheDirectory?.let { dir ->
                        if (!dir.exists() && !dir.mkdirs()) {
                            throw IOException("Failed to create cronet cache directory")
                        }
                        setStoragePath(dir.absolutePath)
                        enableHttpCache(CronetEngine.Builder.HTTP_CACHE_DISK, config.cronetConfig.cacheSizeBytes)
                    }
                } else {
                    enableHttpCache(CronetEngine.Builder.HTTP_CACHE_IN_MEMORY, config.cronetConfig.cacheSizeBytes)
                }

                enablePublicKeyPinningBypassForLocalTrustAnchors(false)
            }

            // Build experimental options JSON for features needing it
            val hostRules = resolver?.buildHostResolverRules()
            val enabledFeatures = mutableListOf<String>()
            if (config.cronetConfig.enableZstd) enabledFeatures.add("EnableZstdV2")

            if (hostRules != null || enabledFeatures.isNotEmpty()) {
                val experimentalJson = JSONObject().apply {
                    if (hostRules != null) {
                        put("HostResolverRules", JSONObject().put("host_resolver_rules", hostRules))
                        put("AsyncDNS", JSONObject().put("enable", true))
                    }
                    if (enabledFeatures.isNotEmpty()) {
                        put("feature_list", JSONObject().put("enable", enabledFeatures.joinToString(",")))
                    }
                }.toString()
                applyExperimentalOptions(builder, experimentalJson)
            }

            return builder.build()
        }

        private fun applyExperimentalOptions(builder: CronetEngine.Builder, json: String) {
            // Try direct cast to ExperimentalCronetEngine.Builder
            if (builder is ExperimentalCronetEngine.Builder) {
                builder.setExperimentalOptions(json)
                return
            }

            // Reflection fallback: access mBuilderDelegate which may be ExperimentalCronetEngine.Builder
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
}
