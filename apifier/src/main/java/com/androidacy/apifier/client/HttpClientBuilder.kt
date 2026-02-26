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
import org.chromium.net.QuicOptions
import java.io.IOException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class HttpClientBuilder(
    private val context: Context,
    private val config: NetworkConfig
) {
    companion object {
        private val IDEMPOTENT_METHODS = setOf("GET", "HEAD")
    }

    fun build(): OkHttpClient {
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

        builder.addInterceptor(CronetCallInterceptor(createCronetEngine()))

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

    @Suppress("UnsafeOptInUsageError")
    private fun createCronetEngine(): CronetEngine {
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

        return provider.createBuilder().apply {
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

            config.cronetConfig.cacheDirectory?.let { dir ->
                if (!dir.exists() && !dir.mkdirs()) {
                    throw IOException("Failed to create cronet cache directory")
                }
                setStoragePath(dir.absolutePath)
                enableHttpCache(CronetEngine.Builder.HTTP_CACHE_DISK, config.cronetConfig.cacheSizeBytes)
            }

            enablePublicKeyPinningBypassForLocalTrustAnchors(false)
        }.build()
    }
}
