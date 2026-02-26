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

/**
 * Thread-safe circuit breaker (closed/open/half-open).
 * @param failureThreshold consecutive failures before opening
 * @param timeoutMs millis before transitioning open to half-open
 */
class CircuitBreaker(
    private val failureThreshold: Int = 5,
    private val timeoutMs: Long = 300_000L
) {
    private var state = STATE_CLOSED
    private var failureCount = 0
    private var lastFailureTime = 0L

    /** True when the breaker is open (rejecting calls). */
    val isOpen: Boolean get() = synchronized(this) { state == STATE_OPEN }

    /** True when the breaker is closed (allowing calls). */
    val isClosed: Boolean get() = synchronized(this) { state == STATE_CLOSED }

    /** Record a successful call. Resets failure count; closes breaker if half-open. */
    @Synchronized
    fun recordSuccess() {
        when (state) {
            STATE_HALF_OPEN -> reset()
            STATE_CLOSED -> failureCount = 0
        }
    }

    /** Record a failed call. Opens breaker after [failureThreshold] consecutive failures. */
    @Synchronized
    fun recordFailure() {
        lastFailureTime = System.currentTimeMillis()
        failureCount++
        if (failureCount >= failureThreshold && state == STATE_CLOSED) {
            state = STATE_OPEN
        }
    }

    /** @return true if a call should be permitted (closed or half-open). */
    @Synchronized
    fun checkState(): Boolean {
        if (state != STATE_OPEN) return true

        if (System.currentTimeMillis() - lastFailureTime >= timeoutMs) {
            state = STATE_HALF_OPEN
            return true
        }
        return false
    }

    /** Force-reset to closed state. */
    @Synchronized
    fun reset() {
        failureCount = 0
        lastFailureTime = 0L
        state = STATE_CLOSED
    }

    companion object {
        private const val STATE_CLOSED = 0
        private const val STATE_OPEN = 1
        private const val STATE_HALF_OPEN = 2
    }
}
