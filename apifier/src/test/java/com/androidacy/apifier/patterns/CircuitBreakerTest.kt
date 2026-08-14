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

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CircuitBreakerTest {

    @Test
    fun opensAfterThresholdConsecutiveFailures() {
        val breaker = CircuitBreaker(failureThreshold = 3, timeoutMs = 100_000L)
        breaker.recordFailure()
        breaker.recordFailure()
        assertTrue(breaker.isClosed)
        assertTrue(breaker.checkState())

        breaker.recordFailure()
        assertTrue(breaker.isOpen)
        assertFalse(breaker.checkState())
    }

    @Test
    fun successResetsFailureCount() {
        val breaker = CircuitBreaker(failureThreshold = 3, timeoutMs = 100_000L)
        breaker.recordFailure()
        breaker.recordFailure()
        breaker.recordSuccess()
        breaker.recordFailure()
        breaker.recordFailure()
        assertTrue(breaker.isClosed)
    }

    @Test
    fun openTransitionsToHalfOpenAfterTimeout() {
        val breaker = CircuitBreaker(failureThreshold = 1, timeoutMs = 100L)
        breaker.recordFailure()
        assertFalse(breaker.checkState())

        Thread.sleep(250)
        assertTrue(breaker.checkState())
    }

    @Test
    fun halfOpenFailureReopens() {
        val breaker = CircuitBreaker(failureThreshold = 1, timeoutMs = 100L)
        breaker.recordFailure()
        Thread.sleep(250)
        assertTrue(breaker.checkState())

        breaker.recordFailure()
        assertFalse(breaker.checkState())
    }

    @Test
    fun halfOpenSuccessClosesBreaker() {
        val breaker = CircuitBreaker(failureThreshold = 1, timeoutMs = 100L)
        breaker.recordFailure()
        Thread.sleep(250)
        assertTrue(breaker.checkState())

        breaker.recordSuccess()
        assertTrue(breaker.isClosed)
    }
}
