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

import kotlin.math.pow
import kotlin.random.Random

/** Tuning parameters for [ExponentialBackoff]. */
internal data class BackoffConfig(
    val baseDelayMs: Long = 1000L,
    val maxDelayMs: Long = 30_000L,
    val multiplier: Double = 2.0,
    val jitterFactor: Double = 0.1
)

/** Computes exponential backoff delays with jitter. */
internal class ExponentialBackoff(private val config: BackoffConfig = BackoffConfig()) {

    /** Delay in millis before the attempt after [attemptNumber], which is a zero-based index. */
    fun calculateDelay(attemptNumber: Int): Long {
        // Past this the power overflows the delay it feeds, and every result is clamped anyway.
        val exponent = attemptNumber.coerceAtMost(20)
        val delay = (config.baseDelayMs * config.multiplier.pow(exponent))
            .toLong()
            .coerceAtMost(config.maxDelayMs)

        val jitter = (delay * config.jitterFactor * Random.nextDouble()).toLong()

        return (delay + jitter).coerceAtMost(config.maxDelayMs)
    }
}
