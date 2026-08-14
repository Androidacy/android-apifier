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
     * Hosts whose system DNS answers are compared against known-good public resolvers before a
     * call to them runs. Empty switches the check off entirely.
     */
    val protectedDomains: List<String> = emptyList(),
    /** Whether a failed comparison refuses the call. Verdicts are computed either way. */
    val enforceProtectedDomains: Boolean = true,
    /** Registers an internal `Log.d`-per-event observer. Advisory only; release logcat is stripped. */
    val logRequests: Boolean = false
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

/** Timeout durations enforced by the transport. */
data class TimeoutConfig(
    val read: Duration = 60.seconds,
    val call: Duration = 90.seconds
) {
    init {
        require(read.isPositive()) { "read timeout must be positive" }
        require(call.isPositive()) { "call timeout must be positive" }
    }
}

/**
 * Per-host circuit breaker. After [failureThreshold] consecutive failed calls to a host,
 * further calls short-circuit with an IOException until [resetTimeoutMs] elapses, then one
 * probe is admitted. A 5xx response or transport failure counts as a failure; any other
 * response counts as a success.
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
    val retryOn5xx: Boolean = true,
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
    private val protectedDomains = mutableListOf<String>()
    var enforceProtectedDomains: Boolean = true
    var logRequests: Boolean = false

    /** Hosts to compare against known-good resolvers before calling them. */
    fun protectedDomains(vararg domains: String) {
        protectedDomains.addAll(domains)
    }

    fun cronet(block: CronetConfigBuilder.() -> Unit) {
        cronetConfig = CronetConfigBuilder().apply(block).build()
    }

    fun timeouts(block: TimeoutConfigBuilder.() -> Unit) {
        timeouts = TimeoutConfigBuilder().apply(block).build()
    }

    fun retry(block: RetryConfigBuilder.() -> Unit) {
        retryConfig = RetryConfigBuilder().apply(block).build()
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
        cookieStorage, headers, dynamicHeaders, protectedDomains.toList(),
        enforceProtectedDomains, logRequests
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

/** DSL builder for [TimeoutConfig]. */
class TimeoutConfigBuilder {
    var read: Duration = 60.seconds
    var call: Duration = 90.seconds

    fun build() = TimeoutConfig(read, call)
}

/** DSL builder for [RetryConfig]. */
class RetryConfigBuilder {
    var maxAttempts: Int = 1
    var retryOn5xx: Boolean = true
    var retryIdempotentOnly: Boolean = true

    fun build() = RetryConfig(maxAttempts, retryOn5xx, retryIdempotentOnly)
}

/** DSL builder for [CircuitBreakerConfig]. */
class CircuitBreakerConfigBuilder {
    var enabled: Boolean = true
    var failureThreshold: Int = 5
    var resetTimeoutMs: Long = 30_000L

    fun build() = CircuitBreakerConfig(enabled, failureThreshold, resetTimeoutMs)
}
