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
package com.androidacy.apifier.observe

import android.util.Log
import com.androidacy.apifier.http.ErrorCode
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.onSubscription
import kotlinx.coroutines.launch
import java.io.Closeable
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Whether an attempt reached a response or failed before one arrived. */
enum class Outcome { SUCCESS, FAILED }

/**
 * One pipeline attempt, reported after apifier's own instrumentation, not Cronet's
 * `RequestFinishedInfo` (its metrics are `-1` sentinels on the platform provider rung).
 *
 * [responseCode] is null when nothing reached the server. [errorCode] is non-null exactly when
 * [outcome] is [Outcome.FAILED]. [willRetry] is true only on a global event whose attempt the
 * retry stage will repeat; a per-request observer never sees one, since it gets only the
 * completing or final event.
 */
data class RequestEvent(
    val outcome: Outcome,
    val errorCode: ErrorCode?,
    val responseCode: Int?,
    val elapsedMillis: Long,
    val ttfbMillis: Long?,
    val bytesSent: Long,
    val bytesReceived: Long,
    val host: String,
    val method: String,
    val attempt: Int,
    val provider: String,
    val willRetry: Boolean
)

/** Receives [RequestEvent]s. Callbacks run off the emitting (network) thread. */
@Deprecated(
    "RequestEvent carries no call identity, but a global observer never needed one. " +
        "Replaced by ApifierClient.events for the client-wide feed; CallOptions.observer is " +
        "unchanged for per-call terminal events.",
    ReplaceWith("events")
)
fun interface RequestObserver {
    fun onEvent(event: RequestEvent)
}

/**
 * Fans a [RequestEvent] out through [events] and, for the attempt that ends a logical call, an
 * optional per-request observer.
 *
 * [emit] uses `tryEmit` and never suspends: a slow or absent collector cannot backpressure the
 * network path. On overflow [events] evicts its oldest buffered event; it never blocks the caller.
 */
@Suppress("DEPRECATION")
internal class Observation(
    dispatcher: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(1)
) : Closeable {

    private val observers = CopyOnWriteArrayList<RequestObserver>()
    private val closed = AtomicBoolean(false)
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)

    // Every unit dispatched off emit() (the compat fan-out and each perRequest callback) holds
    // this open; close() waits for it to hit zero before it stops accepting new work.
    private val pendingDeliveries = AtomicInteger(0)

    private val mutableEvents = MutableSharedFlow<RequestEvent>(
        replay = 0,
        extraBufferCapacity = EVENT_BUFFER_CAPACITY,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    /** Every [RequestEvent] this client's pipeline reports. Collecting never backpressures a call. */
    val events: SharedFlow<RequestEvent> = mutableEvents.asSharedFlow()

    private val collectorSubscribed = CountDownLatch(1)

    // Fans events out to addObserver() registrants for as long as that API exists. Subscribing
    // is forced to finish before the constructor returns below: tryEmit on a replay=0 flow with
    // zero subscribers drops the value, so a collector started fire-and-forget could lose every
    // event emitted before it happened to attach.
    private val compatCollector: Job = scope.launch {
        mutableEvents.onSubscription { collectorSubscribed.countDown() }.collect { event ->
            try {
                for (observer in observers) dispatch(observer, event)
            } finally {
                pendingDeliveries.decrementAndGet()
            }
        }
    }

    init {
        collectorSubscribed.await()
    }

    fun addObserver(observer: RequestObserver) {
        observers.add(observer)
    }

    fun removeObserver(observer: RequestObserver) {
        observers.remove(observer)
    }

    /** Publishes [event] to [events] and, off the calling thread, to [perRequest]. Never throws. */
    fun emit(event: RequestEvent, perRequest: RequestObserver?) {
        if (closed.get()) return
        pendingDeliveries.incrementAndGet()
        if (!mutableEvents.tryEmit(event)) pendingDeliveries.decrementAndGet()
        if (perRequest != null) {
            pendingDeliveries.incrementAndGet()
            scope.launch {
                try {
                    dispatch(perRequest, event)
                } finally {
                    pendingDeliveries.decrementAndGet()
                }
            }
        }
    }

    /** Marks closed, then blocks until every already-emitted event has been delivered. */
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        awaitDrain()
        scope.cancel()
    }

    private fun awaitDrain() {
        val deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(CLOSE_TIMEOUT_SECONDS)
        while (pendingDeliveries.get() > 0 && System.nanoTime() < deadlineNanos) {
            Thread.sleep(DRAIN_POLL_MILLIS)
        }
    }

    private fun dispatch(observer: RequestObserver, event: RequestEvent) {
        try {
            observer.onEvent(event)
        } catch (e: Throwable) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
        }
    }

    private companion object {
        const val CLOSE_TIMEOUT_SECONDS = 5L
        const val DRAIN_POLL_MILLIS = 5L
        const val EVENT_BUFFER_CAPACITY = 1024
    }
}

/**
 * Registered on [Observation] when `NetworkConfig.logRequests` is set. Configured, not injected:
 * one `Log.d` line per event, advisory only since release builds strip logcat. The [RequestEvent]
 * API is the queryable channel for anything a consumer actually needs.
 */
@Suppress("DEPRECATION")
internal class LoggingObserver : RequestObserver {
    override fun onEvent(event: RequestEvent) {
        Log.d(
            TAG,
            "${event.method} ${event.host} attempt=${event.attempt} outcome=${event.outcome} " +
                "code=${event.responseCode} error=${event.errorCode} elapsedMs=${event.elapsedMillis} " +
                "ttfbMs=${event.ttfbMillis} sent=${event.bytesSent} received=${event.bytesReceived} " +
                "provider=${event.provider} willRetry=${event.willRetry}"
        )
    }

    private companion object {
        const val TAG = "Apifier"
    }
}
