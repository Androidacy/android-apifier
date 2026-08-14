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
package com.androidacy.apifier.progress

/** Which half of a call an update describes. */
enum class ProgressDirection { UPLOAD, DOWNLOAD }

/** Callback for tracking byte progress. */
interface ProgressListener {
    /**
     * A request that both sends a body and reads one reports both halves to the same listener, so
     * each direction runs its own count and reaches [done] once.
     *
     * @param bytesTransferred total bytes moved so far in [direction]
     * @param contentLength total expected bytes, or -1 if unknown
     * @param done true when that direction is complete
     */
    fun update(
        bytesTransferred: Long,
        contentLength: Long,
        done: Boolean,
        direction: ProgressDirection
    )
}
