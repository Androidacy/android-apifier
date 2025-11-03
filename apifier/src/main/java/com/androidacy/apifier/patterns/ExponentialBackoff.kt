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
package com.androidacy.apifier.patterns

import kotlin.math.min
import kotlin.math.pow
import kotlin.random.Random

data class BackoffConfig(
    val maxAttempts: Int = 5,
    val baseDelayMs: Long = 1000L,
    val maxDelayMs: Long = 30_000L,
    val multiplier: Double = 2.0,
    val jitterFactor: Double = 0.1
) {
    init {
        require(maxAttempts > 0) { "maxAttempts must be positive" }
        require(baseDelayMs > 0) { "baseDelayMs must be positive" }
        require(maxDelayMs >= baseDelayMs) { "maxDelayMs must be >= baseDelayMs" }
        require(multiplier >= 1.0) { "multiplier must be >= 1.0" }
        require(jitterFactor in 0.0..1.0) { "jitterFactor must be between 0.0 and 1.0" }
    }
}

class ExponentialBackoff(private val config: BackoffConfig = BackoffConfig()) {

    fun calculateDelay(attemptNumber: Int): Long {
        if (attemptNumber >= config.maxAttempts) return -1
        if (attemptNumber < 0) return 0

        val exponent = attemptNumber.coerceAtMost(20)
        val exponentialDelay = (config.baseDelayMs * config.multiplier.pow(exponent))
            .toLong()
            .coerceAtMost(config.maxDelayMs)

        val cappedDelay = min(exponentialDelay, config.maxDelayMs)
        val jitter = (cappedDelay * config.jitterFactor * Random.nextDouble()).toLong()

        return cappedDelay + jitter
    }

    fun shouldRetry(attemptNumber: Int): Boolean = attemptNumber < config.maxAttempts
}
