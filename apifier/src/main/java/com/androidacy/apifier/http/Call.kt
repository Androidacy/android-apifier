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
package com.androidacy.apifier.http

/**
 * A request that has been prepared for execution. A call may be run once.
 */
@Deprecated(
    "The callback- and blocking-based call surface is superseded by the suspend fun send() " +
        "on Requester. Will be removed in 4.0."
)
interface Call {

    fun request(): Request

    /**
     * Runs the call and reports the result on the client's callback executor. Exactly one of
     * [Callback.onResponse] and [Callback.onFailure] runs, and a transport failure arrives as
     * an [ApifierException].
     */
    @Deprecated(
        "Launch the suspend fun send() on a coroutine of your own instead of a Callback. " +
            "Will be removed in 4.0."
    )
    fun enqueue(callback: Callback)

    /**
     * Runs the call and blocks until it finishes.
     *
     * @throws java.io.IOException an [ApifierException] describing the failure.
     */
    @Deprecated(
        "Blocking bridge over the suspend fun send(); call it from a coroutine instead. " +
            "Will be removed in 4.0."
    )
    fun execute(): Response

    @Deprecated(
        "Cancel the coroutine send() runs on instead of this call. Will be removed in 4.0."
    )
    fun cancel()

    @Deprecated(
        "Cancellation state now belongs to the coroutine send() runs on, not this call. " +
            "Will be removed in 4.0."
    )
    fun isCanceled(): Boolean

    @Deprecated(
        "Build calls through ApifierClient.send() directly instead of a Factory. " +
            "Will be removed in 4.0."
    )
    @Suppress("DEPRECATION")
    fun interface Factory {
        fun newCall(request: Request): Call
    }
}
