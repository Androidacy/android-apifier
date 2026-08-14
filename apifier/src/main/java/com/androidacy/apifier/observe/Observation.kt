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
import java.io.Closeable
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

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

/** Receives [RequestEvent]s. Callbacks run on [Observation]'s executor, never the network thread. */
fun interface RequestObserver {
    fun onEvent(event: RequestEvent)
}

/**
 * Fans a [RequestEvent] out to registered global observers and, for the attempt that ends a
 * logical call, an optional per-request observer.
 *
 * [emit] enqueues and returns without waiting: a slow or throwing observer degrades observation,
 * never the caller. Every dispatch is caught so one observer's exception cannot stop another's
 * delivery, or the request thread that called [emit].
 */
internal class Observation(
    // Bounded so a stalled consumer observer accumulates at most QUEUE_CAPACITY events instead of
    // growing without limit; DiscardOldestPolicy keeps the newest telemetry under back-pressure,
    // matching the documented degrade-don't-block posture instead of applying it only in emit().
    private val executor: ExecutorService = ThreadPoolExecutor(
        1, 1, 0L, TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(QUEUE_CAPACITY),
        { runnable -> Thread(runnable, "Apifier-Observation").apply { isDaemon = true } },
        ThreadPoolExecutor.DiscardOldestPolicy()
    )
) : Closeable {

    private val observers = CopyOnWriteArrayList<RequestObserver>()

    fun addObserver(observer: RequestObserver) {
        observers.add(observer)
    }

    fun removeObserver(observer: RequestObserver) {
        observers.remove(observer)
    }

    /**
     * Enqueues [event] and returns without waiting. A call still in flight when [close] has
     * already shut the executor down would otherwise throw [RejectedExecutionException] into the
     * network thread that called this; that is dropped like any other back-pressure event.
     */
    fun emit(event: RequestEvent, perRequest: RequestObserver?) {
        try {
            executor.execute {
                for (observer in observers) dispatch(observer, event)
                perRequest?.let { dispatch(it, event) }
            }
        } catch (e: RejectedExecutionException) {
            // Closed or momentarily saturated past the DiscardOldestPolicy's own retry; either
            // way this event is lost, which is the documented degrade-don't-block posture.
        }
    }

    /** Drains events already queued by [emit], then stops accepting more. */
    override fun close() {
        executor.shutdown()
        try {
            executor.awaitTermination(CLOSE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
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
        const val QUEUE_CAPACITY = 1024
    }
}

/**
 * Registered on [Observation] when `NetworkConfig.logRequests` is set. Configured, not injected:
 * one `Log.d` line per event, advisory only since release builds strip logcat. The [RequestEvent]
 * API is the queryable channel for anything a consumer actually needs.
 */
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
