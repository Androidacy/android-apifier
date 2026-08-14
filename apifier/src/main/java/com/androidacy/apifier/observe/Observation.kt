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
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.takeWhile
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.io.Closeable
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

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

/** One emitted delivery, carried on the internal compat channel alongside its optional per-call target. */
@Suppress("DEPRECATION")
private data class CompatDelivery(val event: RequestEvent, val perRequest: RequestObserver?)

/** Sentinel [close] emits after the last real delivery, to end the compat collector's loop. */
private object CompatEndOfStream

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

    private val mutableEvents = MutableSharedFlow<RequestEvent>(
        replay = 0,
        extraBufferCapacity = EVENT_BUFFER_CAPACITY,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    /** Every [RequestEvent] this client's pipeline reports. Collecting never backpressures a call. */
    val events: SharedFlow<RequestEvent> = mutableEvents.asSharedFlow()

    // Carries both the global fan-out and each perRequest delivery through one buffer, in emit()
    // order, so DROP_OLDEST's "newest survives" guarantee also covers perRequest: a delivery
    // dropped here was never handed to the collector, so nothing about it needs draining on close.
    private val compatChannel = MutableSharedFlow<Any>(
        replay = 0,
        extraBufferCapacity = EVENT_BUFFER_CAPACITY,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    // UNDISPATCHED runs this body on the constructing thread up to its first suspension;
    // SharedFlow.collect registers its subscriber slot before that suspension, so the collector
    // is a subscriber before the constructor returns, and no emit() before it can be missed.
    private val compatCollector: Job = scope.launch(start = CoroutineStart.UNDISPATCHED) {
        compatChannel.takeWhile { it !== CompatEndOfStream }.collect { signal ->
            val delivery = signal as CompatDelivery
            for (observer in observers) dispatch(observer, delivery.event)
            delivery.perRequest?.let { dispatch(it, delivery.event) }
        }
    }

    fun addObserver(observer: RequestObserver) {
        observers.add(observer)
    }

    fun removeObserver(observer: RequestObserver) {
        observers.remove(observer)
    }

    /** Publishes [event] to [events] and, off the calling thread, to [observers] and [perRequest]. Never throws. */
    fun emit(event: RequestEvent, perRequest: RequestObserver?) {
        if (closed.get()) return
        mutableEvents.tryEmit(event)
        compatChannel.tryEmit(CompatDelivery(event, perRequest))
    }

    /**
     * Marks closed, then blocks until every event already handed to the compat collector has
     * been delivered. [CompatEndOfStream] rides the same DROP_OLDEST buffer as those deliveries,
     * so by the time the collector reaches it every delivery still ahead of it in the buffer is
     * already dispatched, and DROP_OLDEST guarantees this newest-emitted value is never the one evicted.
     */
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        compatChannel.tryEmit(CompatEndOfStream)
        runBlocking { withTimeoutOrNull(CLOSE_TIMEOUT_MILLIS) { compatCollector.join() } }
        scope.cancel()
    }

    private fun dispatch(observer: RequestObserver, event: RequestEvent) {
        try {
            observer.onEvent(event)
        } catch (e: Throwable) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
        }
    }

    private companion object {
        const val CLOSE_TIMEOUT_MILLIS = 5_000L
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
