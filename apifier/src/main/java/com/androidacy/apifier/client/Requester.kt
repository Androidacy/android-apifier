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
package com.androidacy.apifier.client

import com.androidacy.apifier.http.MediaType.Companion.toMediaTypeOrNull
import com.androidacy.apifier.http.MultipartBody
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.http.RequestBody.Companion.asRequestBody
import com.androidacy.apifier.http.RequestBody.Companion.toRequestBody
import com.androidacy.apifier.http.Response
import com.androidacy.apifier.observe.RequestObserver
import com.androidacy.apifier.progress.Progress
import kotlinx.coroutines.flow.MutableSharedFlow
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/**
 * What an [ApifierClient] can be asked to do: send one request and get one response.
 *
 * ```
 * val response = client.get("https://example.com/thing")
 * val body = response.use { it.body.string() }
 * ```
 *
 * The settings that vary per call are chosen by deriving a view of the client and calling
 * through it. A view shares the client's engine, connections and cookies, so it is worth no
 * more than the one call it was built for:
 *
 * ```
 * client.maxAttempts(3).timeout(5.seconds).get(url)
 * ```
 *
 * A view has no `close()`. Only the [ApifierClient] itself owns the engine, and only it can
 * shut the engine down.
 */
interface Requester {

    /**
     * Sends [request] and suspends until its response headers arrive.
     *
     * Safe to call from any dispatcher, the main one included: the work that blocks runs on
     * [kotlinx.coroutines.Dispatchers.IO] whatever dispatcher the caller is on.
     *
     * The response body is still arriving when this returns, so close the [Response] once the
     * body has been read. Cancelling the calling coroutine cancels the request.
     *
     * @throws com.androidacy.apifier.http.ApifierException the call failed or was cancelled.
     * @throws IllegalStateException the client is closed.
     */
    suspend fun send(request: Request): Response

    /** GET [url]. See [send]. */
    suspend fun get(url: String): Response = send(Request.Builder().url(url).get().build())

    /** POST [body] to [url] as [contentType]. See [send]. */
    suspend fun post(url: String, body: String, contentType: String = "application/json"): Response =
        send(Request.Builder().url(url).post(body.toRequestBody(contentType.toMediaTypeOrNull())).build())

    /** DELETE [url]. See [send]. */
    suspend fun delete(url: String): Response = send(Request.Builder().url(url).delete().build())

    /** HEAD [url]. See [send]. */
    suspend fun head(url: String): Response = send(Request.Builder().url(url).head().build())

    /** GET [url] as a download. Same request as [get]; attach a [progress] sink to count the bytes. */
    suspend fun download(url: String): Response = get(url)

    /**
     * POSTs [files] to [url] as multipart form data. [fileNames] are the form-data field names,
     * matching [files] by index. See [send].
     *
     * @throws IllegalArgumentException [files] is empty, [files] and [fileNames] differ in size,
     *   or one of [files] does not exist.
     */
    suspend fun upload(url: String, files: List<File>, fileNames: List<String>): Response {
        require(files.isNotEmpty()) { "Files list cannot be empty" }
        require(files.size == fileNames.size) { "Files and fileNames must have the same size" }

        val body = MultipartBody.Builder()
            .setType(MultipartBody.FORM)
            .apply {
                files.forEachIndexed { index, file ->
                    require(file.exists()) { "File does not exist: ${file.absolutePath}" }
                    addFormDataPart(
                        fileNames[index],
                        file.name,
                        file.asRequestBody("application/octet-stream".toMediaTypeOrNull())
                    )
                }
            }
            .build()
        return send(Request.Builder().url(url).post(body).build())
    }

    /** A view whose calls make at most [count] attempts. 1 means no retry. */
    fun maxAttempts(count: Int): Requester

    /** A view whose calls get [duration] for the whole call, across every attempt. */
    fun timeout(duration: Duration): Requester

    /** [timeout] for callers without Kotlin durations. */
    fun timeout(value: Long, unit: TimeUnit): Requester = timeout(unit.toMillis(value).milliseconds)

    /**
     * A view whose calls report their byte counts into [sink]. See [Progress] for what each
     * emission means.
     *
     * Build [sink] with `extraBufferCapacity > 0`. A default `MutableSharedFlow<Progress>()` has
     * no buffer space and `tryEmit` returns false for it every time, so passing one silently
     * receives nothing.
     */
    fun progress(sink: MutableSharedFlow<Progress>): Requester

    /** A view whose calls report their one terminal event to [observer]. */
    @Suppress("DEPRECATION")
    fun observe(observer: RequestObserver): Requester
}
