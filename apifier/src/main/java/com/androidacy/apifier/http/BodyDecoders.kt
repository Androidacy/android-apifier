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

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.okio.decodeFromBufferedSource

/**
 * Decodes the body as JSON on [Dispatchers.IO] and closes it, reading directly off the body's
 * [okio.BufferedSource] so the payload is never held as a whole [String].
 */
@OptIn(ExperimentalSerializationApi::class)
suspend inline fun <reified T> ResponseBody.json(json: Json = Json.Default): T =
    read { json.decodeFromBufferedSource(it) }

/**
 * Streams the body one line at a time off [Dispatchers.IO], closing it when the flow completes
 * or its collector is cancelled.
 *
 * Reads the body's source directly instead of through [read]: [read] dispatches with its own
 * context switch, and a nested one inside this builder body would emit from a coroutine other
 * than the one the flow was collected on, which [Flow] forbids.
 */
fun ResponseBody.lines(): Flow<String> = flow {
    use { body ->
        val source = body.source()
        var line = source.readUtf8Line()
        while (line != null) {
            emit(line)
            line = source.readUtf8Line()
        }
    }
}.flowOn(Dispatchers.IO)
