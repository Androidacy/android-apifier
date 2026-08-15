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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ExponentialBackoffTest {

    @Test
    fun jitteredDelayNeverExceedsMaxDelay() {
        val backoff = ExponentialBackoff(
            BackoffConfig(baseDelayMs = 1000L, maxDelayMs = 1000L, multiplier = 2.0, jitterFactor = 1.0)
        )
        repeat(1000) {
            assertTrue(backoff.calculateDelay(3) <= 1000L)
        }
    }

    @Test
    fun delayGrowsGeometricallyUntilClamp() {
        val backoff = ExponentialBackoff(
            BackoffConfig(baseDelayMs = 100L, maxDelayMs = 100_000L, multiplier = 2.0, jitterFactor = 0.0)
        )
        assertEquals(100L, backoff.calculateDelay(0))
        assertEquals(200L, backoff.calculateDelay(1))
        assertEquals(400L, backoff.calculateDelay(2))
        assertEquals(800L, backoff.calculateDelay(3))
        assertEquals(100_000L, backoff.calculateDelay(10))
    }
}
