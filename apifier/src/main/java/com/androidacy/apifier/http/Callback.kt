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

import java.io.IOException

/** Receives the outcome of a [Call] started with [Call.enqueue]. */
interface Callback {

    /**
     * The server returned a response. The status may still be an error code; check
     * [Response.isSuccessful]. The response body must be read or closed.
     */
    fun onResponse(call: Call, response: Response)

    /** The call did not produce a response. [e] is an [ApifierException]. */
    fun onFailure(call: Call, e: IOException)
}
