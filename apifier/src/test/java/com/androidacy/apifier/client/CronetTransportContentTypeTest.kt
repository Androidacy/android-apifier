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
import com.androidacy.apifier.http.MediaType.Companion.toMediaTypeOrNull
import com.androidacy.apifier.http.Request
import com.androidacy.apifier.http.RequestBody.Companion.toRequestBody
import com.androidacy.apifier.http.Response
import org.chromium.net.CronetProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Drives a request with a lowercase `content-type` header and a body carrying its own media
 * type through a real [CronetTransport] and a real TLS socket, and reads back the bytes it put
 * on the wire. Cronet's [org.chromium.net.UrlRequest] never exposes its built headers, so this
 * is the only way to observe what the transport actually sent.
 */
@RunWith(RobolectricTestRunner::class)
class CronetTransportContentTypeTest {

    /** Production change that fails this: a case-sensitive presence check in `buildUrlRequest`. */
    @Test
    @Suppress("DEPRECATION")
    fun contentTypeIsDetectedRegardlessOfHeaderCase() {
        val keystorePath = Files.createTempFile("cronet-transport-test", ".p12")
        Files.delete(keystorePath)
        // Conscrypt's EC AlgorithmParameters engine (installed ahead of SunEC by Robolectric)
        // rejects the NamedGroup init SunJSSE's SSLServerSocket does at construction time; drop
        // it for the plain java.net TLS socket this test stands up, and put it back after.
        val conscryptPosition = Security.getProviders().indexOfFirst { it.name == "Conscrypt" } + 1
        val conscrypt = if (conscryptPosition > 0) Security.getProvider("Conscrypt") else null
        conscrypt?.let { Security.removeProvider(it.name) }
        try {
            generateSelfSignedKeystore(keystorePath.toString())
            val serverContext = serverSslContext(keystorePath.toString())
            val server = serverContext.serverSocketFactory.createServerSocket(0) as SSLServerSocket

            val previousFactory = HttpsURLConnection.getDefaultSSLSocketFactory()
            val previousVerifier = HttpsURLConnection.getDefaultHostnameVerifier()
            HttpsURLConnection.setDefaultSSLSocketFactory(trustAllContext().socketFactory)
            HttpsURLConnection.setDefaultHostnameVerifier(HostnameVerifier { _, _ -> true })

            val context = ApplicationProvider.getApplicationContext<Context>()
            val provider = Class.forName("org.chromium.net.impl.JavaCronetProvider")
                .getConstructor(Context::class.java)
                .newInstance(context) as CronetProvider
            val engine = provider.createBuilder().build()
            val transport = CronetTransport(engine, READ_TIMEOUT_MS)

            val requestHead = AtomicReference<String>()
            val acceptedRequest = CountDownLatch(1)
            val listener = Thread {
                (server.accept() as SSLSocket).use { socket ->
                    val reader = BufferedReader(
                        InputStreamReader(socket.inputStream, StandardCharsets.US_ASCII)
                    )
                    val head = StringBuilder()
                    var line = reader.readLine()
                    while (!line.isNullOrEmpty()) {
                        head.append(line).append('\n')
                        line = reader.readLine()
                    }
                    requestHead.set(head.toString())
                    acceptedRequest.countDown()
                    socket.outputStream.writeMinimalResponse()
                }
            }.apply { isDaemon = true; start() }

            try {
                val body = "{}".toRequestBody("application/octet-stream".toMediaTypeOrNull())
                val request = Request.Builder()
                    .url("https://127.0.0.1:${server.localPort}/")
                    .header("content-type", "text/x-explicit")
                    .post(body)
                    .build()

                val done = CountDownLatch(1)
                val result = AtomicReference<Response?>()
                transport.newCall(request, null).enqueue(object : CallOutcome {
                    override fun onSuccess(response: Response) {
                        result.set(response)
                        done.countDown()
                    }

                    override fun onFailure(e: IOException) = done.countDown()
                })

                assertTrue(
                    "the server never accepted a connection",
                    acceptedRequest.await(TERMINAL_WAIT_SECONDS, TimeUnit.SECONDS)
                )
                assertTrue(
                    "no terminal callback within ${TERMINAL_WAIT_SECONDS}s",
                    done.await(TERMINAL_WAIT_SECONDS, TimeUnit.SECONDS)
                )
                result.get()?.close()

                val contentTypeLines = requestHead.get().lines()
                    .filter { it.startsWith("content-type:", ignoreCase = true) }
                assertEquals("expected exactly one content-type header on the wire", 1, contentTypeLines.size)
                assertTrue(
                    "expected the explicit header value, got ${contentTypeLines.single()}",
                    contentTypeLines.single().contains("text/x-explicit")
                )
            } finally {
                transport.shutdown()
                runCatching { engine.shutdown() }
                server.close()
                listener.join(TimeUnit.SECONDS.toMillis(TERMINAL_WAIT_SECONDS))
                HttpsURLConnection.setDefaultSSLSocketFactory(previousFactory)
                HttpsURLConnection.setDefaultHostnameVerifier(previousVerifier)
            }
        } finally {
            conscrypt?.let { Security.insertProviderAt(it, conscryptPosition) }
            Files.deleteIfExists(keystorePath)
        }
    }

    private fun OutputStream.writeMinimalResponse() {
        write(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .toByteArray(StandardCharsets.US_ASCII)
        )
        flush()
    }

    private fun keytoolPath(): String {
        val fromJavaHome = File(System.getProperty("java.home"), "bin/keytool")
        return if (fromJavaHome.exists()) fromJavaHome.absolutePath else "keytool"
    }

    private fun generateSelfSignedKeystore(path: String) {
        val process = ProcessBuilder(
            keytoolPath(), "-genkeypair",
            "-alias", "test",
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "1",
            "-dname", "CN=127.0.0.1",
            "-keystore", path,
            "-storepass", KEYSTORE_PASSWORD,
            "-keypass", KEYSTORE_PASSWORD,
            "-storetype", "PKCS12"
        ).redirectErrorStream(true).start()
        val finished = process.waitFor(TERMINAL_WAIT_SECONDS, TimeUnit.SECONDS)
        val output = process.inputStream.bufferedReader().readText()
        require(finished && process.exitValue() == 0) { "keytool failed: $output" }
    }

    private fun serverSslContext(keystorePath: String): SSLContext {
        val keyStore = KeyStore.getInstance("PKCS12")
        FileInputStream(keystorePath).use { keyStore.load(it, KEYSTORE_PASSWORD.toCharArray()) }
        val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManagerFactory.init(keyStore, KEYSTORE_PASSWORD.toCharArray())
        return SSLContext.getInstance("TLS").apply {
            init(keyManagerFactory.keyManagers, null, null)
        }
    }

    /** The server certificate is a throwaway generated per test run, so the client must not check it. */
    private fun trustAllContext(): SSLContext {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
        return SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(trustAll), null)
        }
    }

    private companion object {
        const val READ_TIMEOUT_MS = 5_000L
        const val TERMINAL_WAIT_SECONDS = 30L
        const val KEYSTORE_PASSWORD = "changeit"
    }
}
