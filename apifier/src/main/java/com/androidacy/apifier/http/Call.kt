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
interface Call {

    fun request(): Request

    /**
     * Runs the call and reports the result on the client's callback executor. Exactly one of
     * [Callback.onResponse] and [Callback.onFailure] runs, and a transport failure arrives as
     * an [ApifierException].
     */
    fun enqueue(callback: Callback)

    /**
     * Runs the call and blocks until it finishes.
     *
     * @throws java.io.IOException an [ApifierException] describing the failure.
     */
    @Deprecated("Blocking bridge over the async path; prefer enqueue.")
    fun execute(): Response

    fun cancel()

    fun isCanceled(): Boolean

    fun interface Factory {
        fun newCall(request: Request): Call
    }
}
