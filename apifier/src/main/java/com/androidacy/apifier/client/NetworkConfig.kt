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
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

data class NetworkConfig(
    val cronetConfig: CronetConfig = CronetConfig(),
    val timeouts: TimeoutConfig = TimeoutConfig(),
    val connectionPool: ConnectionPoolConfig = ConnectionPoolConfig(),
    val retryConfig: RetryConfig = RetryConfig(),
    val cookieStorage: CookieStorage? = null,
    val headers: Map<String, String> = emptyMap(),
    val dynamicHeaders: Map<String, () -> String> = emptyMap()
)

data class CronetConfig(
    val enableQuic: Boolean = true,
    val enableHttp2: Boolean = true,
    val enableBrotli: Boolean = true,
    val quicHints: List<Pair<String, Int>> = emptyList(),
    val cacheDirectory: File? = null,
    val cacheSizeBytes: Long = 256 * 1024 * 1024, // 256MB default
    val enableDnsOverHttps: Boolean = true,
    val enableStaleDns: Boolean = true
) {
    init {
        require(cacheSizeBytes > 0) { "cacheSizeBytes must be positive" }
        quicHints.forEach { (host, port) ->
            require(host.isNotBlank()) { "QUIC hint host cannot be blank" }
            require(port in 1..65535) { "QUIC hint port must be between 1 and 65535" }
        }
    }
}

data class TimeoutConfig(
    val connect: Duration = 5.seconds,
    val read: Duration = 60.seconds,
    val write: Duration = 20.seconds,
    val call: Duration = 90.seconds
) {
    init {
        require(connect.isPositive()) { "connect timeout must be positive" }
        require(read.isPositive()) { "read timeout must be positive" }
        require(write.isPositive()) { "write timeout must be positive" }
        require(call.isPositive()) { "call timeout must be positive" }
    }
}

data class ConnectionPoolConfig(
    val maxIdleConnections: Int = Runtime.getRuntime().availableProcessors() * 4,
    val keepAliveDuration: Duration = 2.minutes
) {
    init {
        require(maxIdleConnections > 0) { "maxIdleConnections must be positive" }
        require(keepAliveDuration.isPositive()) { "keepAliveDuration must be positive" }
    }
}

data class RetryConfig(
    val maxAttempts: Int = 1,
    val retryOn5xx: Boolean = true,
    val retryIdempotentOnly: Boolean = true
) {
    init {
        require(maxAttempts > 0) { "maxAttempts must be positive" }
    }
}

class NetworkConfigBuilder {
    private var cronetConfig = CronetConfig()
    private var timeouts = TimeoutConfig()
    private var connectionPool = ConnectionPoolConfig()
    private var retryConfig = RetryConfig()
    private var cookieStorage: CookieStorage? = null
    private val headers = mutableMapOf<String, String>()
    private val dynamicHeaders = mutableMapOf<String, () -> String>()

    fun cronet(block: CronetConfigBuilder.() -> Unit) {
        cronetConfig = CronetConfigBuilder().apply(block).build()
    }

    fun timeouts(block: TimeoutConfigBuilder.() -> Unit) {
        timeouts = TimeoutConfigBuilder().apply(block).build()
    }

    fun connectionPool(block: ConnectionPoolConfigBuilder.() -> Unit) {
        connectionPool = ConnectionPoolConfigBuilder().apply(block).build()
    }

    fun retry(block: RetryConfigBuilder.() -> Unit) {
        retryConfig = RetryConfigBuilder().apply(block).build()
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
        cronetConfig, timeouts, connectionPool, retryConfig,
        cookieStorage, headers, dynamicHeaders
    )
}

class CronetConfigBuilder {
    var enableQuic = true
    var enableHttp2 = true
    var enableBrotli = true
    var quicHints = mutableListOf<Pair<String, Int>>()
    var cacheDirectory: File? = null
    var cacheSizeBytes: Long = 256 * 1024 * 1024
    var enableDnsOverHttps = true
    var enableStaleDns = true

    fun quicHint(host: String, port: Int = 443, alternatePort: Int = 443) {
        quicHints.add(host to alternatePort)
    }

    fun build() = CronetConfig(
        enableQuic, enableHttp2, enableBrotli, quicHints,
        cacheDirectory, cacheSizeBytes, enableDnsOverHttps, enableStaleDns
    )
}

class TimeoutConfigBuilder {
    var connect: Duration = 5.seconds
    var read: Duration = 60.seconds
    var write: Duration = 20.seconds
    var call: Duration = 90.seconds

    fun build() = TimeoutConfig(connect, read, write, call)
}

class ConnectionPoolConfigBuilder {
    var maxIdleConnections: Int = Runtime.getRuntime().availableProcessors() * 4
    var keepAliveDuration: Duration = 2.minutes

    fun build() = ConnectionPoolConfig(maxIdleConnections, keepAliveDuration)
}

class RetryConfigBuilder {
    var maxAttempts: Int = 1
    var retryOn5xx: Boolean = true
    var retryIdempotentOnly: Boolean = true

    fun build() = RetryConfig(maxAttempts, retryOn5xx, retryIdempotentOnly)
}
