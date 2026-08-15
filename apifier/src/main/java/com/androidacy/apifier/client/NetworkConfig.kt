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

import com.androidacy.apifier.observe.RequestObserver
import com.androidacy.apifier.security.CookieStorage
import java.io.File
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** Top-level configuration for [ApifierClient]. */
data class NetworkConfig(
    val cronetConfig: CronetConfig = CronetConfig(),
    val timeouts: TimeoutConfig = TimeoutConfig(),
    val retryConfig: RetryConfig = RetryConfig(),
    val circuitBreakerConfig: CircuitBreakerConfig = CircuitBreakerConfig(),
    val cookieStorage: CookieStorage? = null,
    val headers: Map<String, String> = emptyMap(),
    val dynamicHeaders: Map<String, () -> String> = emptyMap(),
    /**
     * Whether a call is refused while the platform resolver fails qualification. The checks run
     * for every client either way; only the refusal is opt-in. A no-op while [hostIpPins] is
     * non-empty: pins force enforcement on regardless of this flag.
     */
    val ensureTrustworthyResolver: Boolean = false,
    /**
     * Per-host address pins; see [com.androidacy.apifier.dns.hostIpPins]. Declaring a pin for a
     * host forces enforcement on for the whole client, making [ensureTrustworthyResolver] a
     * no-op.
     */
    val hostIpPins: Map<String, Set<String>> = emptyMap(),
    /** Registers an internal `Log.d`-per-event observer. Advisory only; release logcat is stripped. */
    val logRequests: Boolean = false,
    /** Observer used for a call whose [com.androidacy.apifier.client.Requester.observe] set none. */
    @Suppress("DEPRECATION")
    val defaultObserver: RequestObserver? = null
)

/** Cronet engine transport settings. */
data class CronetConfig(
    val enableQuic: Boolean = true,
    val enableHttp2: Boolean = true,
    val enableBrotli: Boolean = true,
    val quicHints: List<Triple<String, Int, Int>> = emptyList(),
    val cacheDirectory: File? = null,
    val cacheSizeBytes: Long = 256 * 1024 * 1024, // 256MB default
    /** Gates Cronet's built-in resolver, stale-DNS serving, and host-cache persistence. */
    val enableBuiltInDnsResolver: Boolean = true,
    val enableStaleDns: Boolean = true
) {
    init {
        require(cacheSizeBytes > 0) { "cacheSizeBytes must be positive" }
        quicHints.forEach { (host, port, alternatePort) ->
            require(host.isNotBlank()) { "QUIC hint host cannot be blank" }
            require(port in 1..65535) { "QUIC hint port must be between 1 and 65535" }
            require(alternatePort in 1..65535) { "QUIC hint alternatePort must be between 1 and 65535" }
        }
    }
}

/** Timeout durations, each enforced by the pipeline; the transport enforces neither. */
data class TimeoutConfig(
    /** Longest gap between body chunks once the response headers arrive; enforced on the body pipe. */
    val read: Duration = 60.seconds,
    /** Budget for the whole call across every attempt; enforced by a scheduled task in the pipeline. */
    val call: Duration = 90.seconds
) {
    init {
        require(read.isPositive()) { "read timeout must be positive" }
        require(call.isPositive()) { "call timeout must be positive" }
    }
}

/**
 * Per-host circuit breaker. After [failureThreshold] consecutive failed calls to a host,
 * calls to it fail immediately with `ApifierException.CircuitOpen` until [resetTimeoutMs] has
 * passed since the most recent failure. A 5xx response or a transport failure counts as a
 * failure, as does a call that burns its entire timeout; a cancel by the caller does not, and
 * any other response counts as a success.
 */
data class CircuitBreakerConfig(
    val enabled: Boolean = true,
    val failureThreshold: Int = 5,
    val resetTimeoutMs: Long = 30_000L
) {
    init {
        require(failureThreshold > 0) { "failureThreshold must be positive" }
        require(resetTimeoutMs > 0) { "resetTimeoutMs must be positive" }
    }
}

/** Retry policy for failed requests. */
data class RetryConfig(
    val maxAttempts: Int = 1,
    /** Retry a response whose status is 500-599. */
    val retryOn5xx: Boolean = true,
    /** Retry only requests whose method is RFC 9110 s9.2.2 idempotent. */
    val retryIdempotentOnly: Boolean = true
) {
    init {
        require(maxAttempts > 0) { "maxAttempts must be positive" }
    }
}

/** DSL builder for [NetworkConfig]. */
class NetworkConfigBuilder {
    private var cronetConfig = CronetConfig()
    private var timeouts = TimeoutConfig()
    private var retryConfig = RetryConfig()
    private var circuitBreakerConfig = CircuitBreakerConfig()
    private var cookieStorage: CookieStorage? = null
    private val headers = mutableMapOf<String, String>()
    private val dynamicHeaders = mutableMapOf<String, () -> String>()
    private var ensureTrustworthyResolver: Boolean = false
    internal var hostIpPins: Map<String, Set<String>> = emptyMap()
    var logRequests: Boolean = false
    @Suppress("DEPRECATION")
    private var defaultObserver: RequestObserver? = null

    /** Refuses calls while the platform resolver fails qualification; see [NetworkConfig.ensureTrustworthyResolver]. */
    fun ensureTrustworthyResolver(enabled: Boolean) {
        ensureTrustworthyResolver = enabled
    }

    /** Default attempt ceiling for every call this client makes; see [Requester.maxAttempts]. */
    fun maxAttempts(count: Int) {
        retryConfig = retryConfig.copy(maxAttempts = count)
    }

    /** Default call budget for every call this client makes; see [Requester.timeout]. */
    fun timeout(duration: Duration) {
        timeouts = timeouts.copy(call = duration)
    }

    /**
     * Default terminal-event observer for every call this client makes; see [Requester.observe].
     * `progress` has no builder counterpart: unlike an attempt ceiling or a timeout, a byte-count
     * sink shared by every concurrent call would interleave their counts into one meaningless
     * stream, so it stays a per-call-only setting.
     */
    @Suppress("DEPRECATION")
    fun observe(observer: RequestObserver) {
        defaultObserver = observer
    }

    fun cronet(block: CronetConfigBuilder.() -> Unit) {
        cronetConfig = CronetConfigBuilder().apply(block).build()
    }

    fun timeouts(block: TimeoutConfigBuilder.() -> Unit) {
        timeouts = TimeoutConfigBuilder().apply { carriedCall = timeouts.call }.apply(block).build()
    }

    fun retry(block: RetryConfigBuilder.() -> Unit) {
        retryConfig = RetryConfigBuilder().apply { carriedMaxAttempts = retryConfig.maxAttempts }.apply(block).build()
    }

    fun circuitBreaker(block: CircuitBreakerConfigBuilder.() -> Unit) {
        circuitBreakerConfig = CircuitBreakerConfigBuilder().apply(block).build()
    }

    fun cookieStorage(storage: CookieStorage) {
        cookieStorage = storage
    }

    fun header(name: String, value: String) {
        headers[name] = value
    }

    fun dynamicHeader(name: String, valueProvider: () -> String) {
        dynamicHeaders[name] = valueProvider
    }

    fun build() = NetworkConfig(
        cronetConfig, timeouts, retryConfig, circuitBreakerConfig,
        cookieStorage, headers, dynamicHeaders,
        ensureTrustworthyResolver, hostIpPins, logRequests, defaultObserver
    )
}

/** DSL builder for [CronetConfig]. */
class CronetConfigBuilder {
    var enableQuic = true
    var enableHttp2 = true
    var enableBrotli = true
    var quicHints = mutableListOf<Triple<String, Int, Int>>()
    var cacheDirectory: File? = null
    var cacheSizeBytes: Long = 256 * 1024 * 1024
    var enableBuiltInDnsResolver = true
    var enableStaleDns = true

    fun quicHint(host: String, port: Int = 443, alternatePort: Int = 443) {
        quicHints.add(Triple(host, port, alternatePort))
    }

    fun build() = CronetConfig(
        enableQuic, enableHttp2, enableBrotli, quicHints,
        cacheDirectory, cacheSizeBytes, enableBuiltInDnsResolver, enableStaleDns
    )
}

/** DSL builder for [TimeoutConfig]. No `call` setter here; see [NetworkConfigBuilder.timeout]. */
class TimeoutConfigBuilder {
    var read: Duration = 60.seconds

    /** Set by [NetworkConfigBuilder.timeouts] before the block runs, to preserve a call budget set through [NetworkConfigBuilder.timeout]. */
    internal var carriedCall: Duration = TimeoutConfig().call

    fun build() = TimeoutConfig(read, carriedCall)
}

/** DSL builder for [RetryConfig]. No `maxAttempts` setter here; see [NetworkConfigBuilder.maxAttempts]. */
class RetryConfigBuilder {
    var retryOn5xx: Boolean = true
    var retryIdempotentOnly: Boolean = true

    /** Set by [NetworkConfigBuilder.retry] before the block runs, to preserve a ceiling set through [NetworkConfigBuilder.maxAttempts]. */
    internal var carriedMaxAttempts: Int = RetryConfig().maxAttempts

    fun build() = RetryConfig(carriedMaxAttempts, retryOn5xx, retryIdempotentOnly)
}

/** DSL builder for [CircuitBreakerConfig]. */
class CircuitBreakerConfigBuilder {
    var enabled: Boolean = true
    var failureThreshold: Int = 5
    var resetTimeoutMs: Long = 30_000L

    fun build() = CircuitBreakerConfig(enabled, failureThreshold, resetTimeoutMs)
}
