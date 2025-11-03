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
import com.androidacy.apifier.progress.ProgressListener
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File

class ApifierClient(context: Context, config: NetworkConfig) {

    val client: OkHttpClient = HttpClientBuilder(context, config).build()

    fun get(url: String, callback: Callback): Call {
        val request = Request.Builder().url(url).get().build()
        val call = client.newCall(request)
        call.enqueue(callback)
        return call
    }

    fun post(url: String, body: String, contentType: String = "application/json", callback: Callback): Call {
        val requestBody = body.toRequestBody(contentType.toMediaTypeOrNull())
        val request = Request.Builder().url(url).post(requestBody).build()
        val call = client.newCall(request)
        call.enqueue(callback)
        return call
    }

    fun delete(url: String, callback: Callback): Call {
        val request = Request.Builder().url(url).delete().build()
        val call = client.newCall(request)
        call.enqueue(callback)
        return call
    }

    fun head(url: String, callback: Callback): Call {
        val request = Request.Builder().url(url).head().build()
        val call = client.newCall(request)
        call.enqueue(callback)
        return call
    }

    fun download(url: String, progressListener: ProgressListener, callback: Callback): Call {
        val request = Request.Builder()
            .url(url)
            .tag(ProgressListener::class.java, progressListener)
            .get()
            .build()
        val call = client.newCall(request)
        call.enqueue(callback)
        return call
    }

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

        val call = client.newCall(requestBuilder.build())
        call.enqueue(callback)
        return call
    }

    companion object {
        operator fun invoke(context: Context, block: NetworkConfigBuilder.() -> Unit): ApifierClient {
            val config = NetworkConfigBuilder().apply(block).build()
            return ApifierClient(context, config)
        }
    }
}
