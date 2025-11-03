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

import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class CircuitBreaker(
    private val failureThreshold: Int = 5,
    private val timeoutMs: Long = 300_000L
) {
    private val state = AtomicInteger(STATE_CLOSED)
    private val failureCount = AtomicInteger(0)
    private val lastFailureTime = AtomicLong(0L)

    val isOpen: Boolean
        get() = state.get() == STATE_OPEN

    val isClosed: Boolean
        get() = state.get() == STATE_CLOSED

    fun recordSuccess() {
        when (state.get()) {
            STATE_HALF_OPEN -> reset()
            STATE_CLOSED -> failureCount.set(0)
        }
    }

    fun recordFailure() {
        lastFailureTime.set(System.currentTimeMillis())

        val count = failureCount.incrementAndGet()
        if (count >= failureThreshold) {
            state.compareAndSet(STATE_CLOSED, STATE_OPEN)
        }
    }

    fun checkState(): Boolean {
        if (state.get() != STATE_OPEN) return true

        val now = System.currentTimeMillis()
        val elapsed = now - lastFailureTime.get()

        if (elapsed >= timeoutMs && state.compareAndSet(STATE_OPEN, STATE_HALF_OPEN)) {
            return true
        }

        return false
    }

    fun reset() {
        failureCount.set(0)
        lastFailureTime.set(0L)
        state.set(STATE_CLOSED)
    }

    companion object {
        private const val STATE_CLOSED = 0
        private const val STATE_OPEN = 1
        private const val STATE_HALF_OPEN = 2
    }
}
