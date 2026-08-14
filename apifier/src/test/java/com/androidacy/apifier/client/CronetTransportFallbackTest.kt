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
import androidx.test.core.app.ApplicationProvider
import com.androidacy.apifier.http.ApifierException
import com.androidacy.apifier.http.Call
import com.androidacy.apifier.http.Callback
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.http.Response
import org.chromium.net.CronetProvider
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Runs a real engine on the Java fallback provider, the one rung reachable without native
 * Cronet.
 */
@RunWith(RobolectricTestRunner::class)
class CronetTransportFallbackTest {

    /**
     * A failure before any response reaches the caller.
     *
     * Cronet hands `onFailed` a null [org.chromium.net.UrlResponseInfo] when it fails before
     * response headers, while the raw `UrlRequest.Callback` annotates that parameter non-null.
     * A Kotlin callback declared against the raw type therefore takes a generated null check on
     * the most common failure there is, and Cronet swallows the resulting exception inside its
     * own frame, so no terminal callback ever runs and the call hangs.
     */
    @Test
    @Suppress("DEPRECATION")
    fun failureBeforeResponseDeliversTerminalError() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val provider = Class.forName("org.chromium.net.impl.JavaCronetProvider")
            .getConstructor(Context::class.java)
            .newInstance(context) as CronetProvider
        val engine = provider.createBuilder().build()
        val transport = CronetTransport(engine, READ_TIMEOUT_MS)

        try {
            val closedPort = ServerSocket(0).use { it.localPort }
            val request = Request.Builder().url("https://127.0.0.1:$closedPort/").get().build()

            val failure = AtomicReference<IOException?>()
            val response = AtomicReference<Response?>()
            val done = CountDownLatch(1)
            transport.newCall(request, null).enqueue(object : Callback {
                override fun onResponse(call: Call, response1: Response) {
                    response1.close()
                    response.set(response1)
                    done.countDown()
                }

                override fun onFailure(call: Call, e: IOException) {
                    failure.set(e)
                    done.countDown()
                }
            })

            assertTrue(
                "no terminal callback within ${TERMINAL_WAIT_SECONDS}s",
                done.await(TERMINAL_WAIT_SECONDS, TimeUnit.SECONDS)
            )
            assertNull("expected no response from a closed port", response.get())
            assertTrue(
                "expected an ApifierException, got ${failure.get()}",
                failure.get() is ApifierException.Transport
            )
        } finally {
            transport.shutdown()
            runCatching { engine.shutdown() }
        }
    }

    private companion object {
        const val READ_TIMEOUT_MS = 5_000L
        const val TERMINAL_WAIT_SECONDS = 30L
    }
}
