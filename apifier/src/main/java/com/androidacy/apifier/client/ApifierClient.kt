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

import android.content.Context
import com.androidacy.apifier.http.Call
import com.androidacy.apifier.http.Callback
import com.androidacy.apifier.http.MediaType.Companion.toMediaTypeOrNull
import com.androidacy.apifier.http.MultipartBody
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.http.RequestBody.Companion.asRequestBody
import com.androidacy.apifier.http.RequestBody.Companion.toRequestBody
import com.androidacy.apifier.progress.ProgressListener
import java.io.File

/** Tag marker to skip automatic retries on a per-request basis. */
object NoRetry

/** Marks this request to skip automatic retries. */
fun Request.Builder.noRetry(): Request.Builder = tag(NoRetry::class.java, NoRetry)

/**
 * HTTP client backed by Cronet.
 * @param context Android context for Cronet provider initialization
 * @param config network and transport configuration
 */
class ApifierClient(context: Context, config: NetworkConfig) {

    private val httpClientBuilder = HttpClientBuilder(context, config)

    /** Transport the helpers enqueue on, and the entry point for hand-built requests. */
    val transport: CronetTransport =
        CronetTransport(httpClientBuilder.build(), config.timeouts.read.inWholeMilliseconds)

    /**
     * True when DoH resolution succeeded and Cronet host rules were installed. False means the
     * client degraded to system DNS, most commonly because it was constructed on the main
     * thread (where the blocking DoH/provider I/O is skipped) or the network was unavailable.
     */
    @Suppress("DEPRECATION")
    val dohActive: Boolean get() = httpClientBuilder.dohActive

    /**
     * Provider selection outcome in ladder order. Keys are `name:version`, values are the
     * `HttpClientBuilder.PROVIDER_*` statuses.
     */
    val providerReport: Map<String, String> get() = httpClientBuilder.providerReport

    /** Enqueues an async GET. Returns the [Call] for cancellation. */
    fun get(url: String, callback: Callback): Call =
        enqueue(Request.Builder().url(url).get().build(), callback)

    /** Enqueues an async POST. [contentType] defaults to JSON. Returns the [Call] for cancellation. */
    fun post(url: String, body: String, contentType: String = "application/json", callback: Callback): Call {
        val requestBody = body.toRequestBody(contentType.toMediaTypeOrNull())
        return enqueue(Request.Builder().url(url).post(requestBody).build(), callback)
    }

    /** Enqueues an async DELETE. Returns the [Call] for cancellation. */
    fun delete(url: String, callback: Callback): Call =
        enqueue(Request.Builder().url(url).delete().build(), callback)

    /** Enqueues an async HEAD. Returns the [Call] for cancellation. */
    fun head(url: String, callback: Callback): Call =
        enqueue(Request.Builder().url(url).head().build(), callback)

    /** GET with progress tracking via [ProgressListener]. */
    fun download(url: String, progressListener: ProgressListener, callback: Callback): Call {
        val request = Request.Builder()
            .url(url)
            .tag(ProgressListener::class.java, progressListener)
            .get()
            .build()
        return enqueue(request, callback)
    }

    /** Multipart file upload. [fileNames] are form-data field names matching [files] by index. */
    fun upload(
        url: String,
        files: List<File>,
        fileNames: List<String>,
        progressListener: ProgressListener? = null,
        callback: Callback
    ): Call {
        require(files.isNotEmpty()) { "Files list cannot be empty" }
        require(files.size == fileNames.size) { "Files and fileNames must have the same size" }

        val requestBody = MultipartBody.Builder()
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

        val requestBuilder = Request.Builder().url(url).post(requestBody)

        if (progressListener != null) {
            requestBuilder.tag(ProgressListener::class.java, progressListener)
        }

        return enqueue(requestBuilder.build(), callback)
    }

    private fun enqueue(request: Request, callback: Callback): Call =
        transport.newCall(request).also { it.enqueue(callback) }

    companion object {
        operator fun invoke(context: Context, block: NetworkConfigBuilder.() -> Unit): ApifierClient {
            val config = NetworkConfigBuilder().apply(block).build()
            return ApifierClient(context, config)
        }
    }
}
