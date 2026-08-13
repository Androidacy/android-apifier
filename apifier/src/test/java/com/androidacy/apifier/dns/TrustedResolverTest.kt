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
package com.androidacy.apifier.dns

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/**
 * Drives the real [TrustedResolver] against local TLS servers built from the committed
 * keystores. Fakes cannot cover this: every other test in the package supplies the exception
 * it wants, so only a real handshake proves a rejected certificate is reported as rejection
 * rather than as unavailability.
 */
class TrustedResolverTest {

    private val passphrase = "apifier-test".toCharArray()
    private val closeables = mutableListOf<Closeable>()
    private lateinit var trust: PinnedRootTrust
    private lateinit var dnsResponse: ByteArray

    @Before
    fun setUp() {
        val ca = KeyStore.getInstance("PKCS12")
        resource("dns/test_ca.p12").use { ca.load(it, passphrase) }
        trust = PinnedRootTrust(listOf(ca.getCertificate("ca") as X509Certificate))
        dnsResponse = resource("dns/cloudflare_com_a_response.bin").use { it.readBytes() }
    }

    @After
    fun tearDown() {
        closeables.forEach { runCatching { it.close() } }
    }

    @Test
    fun selfSignedChainIsCertificateRejected() {
        val server = tlsServer("dns/test_selfsigned.p12", "200 OK")

        assertThrows(CertificateRejectedException::class.java) {
            resolverFor(server.port).query("cloudflare.com")
        }
    }

    @Test
    fun validChainWithNonCoveringSanIsCertificateRejected() {
        val server = tlsServer("dns/test_leaf_wrong_san.p12", "200 OK")

        assertThrows(CertificateRejectedException::class.java) {
            resolverFor(server.port).query("cloudflare.com")
        }
    }

    @Test
    fun closedPortIsResolverUnavailable() {
        val closed = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = closed.localPort
        closed.close()

        assertThrows(ResolverUnavailableException::class.java) {
            resolverFor(port).query("cloudflare.com")
        }
    }

    @Test
    fun abortBeforeHandshakeIsResolverUnavailable() {
        val server = abortingServer()

        assertThrows(ResolverUnavailableException::class.java) {
            resolverFor(server.port).query("cloudflare.com")
        }
    }

    @Test
    fun nonOkStatusIsResolverUnavailable() {
        val server = tlsServer("dns/test_leaf_covering_localhost.p12", "500 Internal Server Error")

        assertThrows(ResolverUnavailableException::class.java) {
            resolverFor(server.port).query("cloudflare.com")
        }
    }

    @Test
    fun postHandshakeStallIsResolverUnavailable() {
        val server = stallingTlsServer("dns/test_leaf_covering_localhost.p12")

        assertThrows(ResolverUnavailableException::class.java) {
            resolverFor(server.port).query("cloudflare.com")
        }
    }

    @Test
    fun rejectionFlagIsClearedBetweenQueries() {
        val rejecting = tlsServer("dns/test_selfsigned.p12", "200 OK")
        assertThrows(CertificateRejectedException::class.java) {
            resolverFor(rejecting.port).query("cloudflare.com")
        }

        val good = tlsServer("dns/test_leaf_covering_localhost.p12", "200 OK")
        val answer = resolverFor(good.port).query("cloudflare.com")

        assertEquals(listOf("104.16.132.229", "104.16.133.229"), answer.addresses)
    }

    @Test
    fun resolverBackoffAfterFailures() {
        val closed = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = closed.localPort
        closed.close()
        var now = 1_000L
        val resolver = TrustedResolver(
            name = "test",
            endpoint = "https://127.0.0.1:$port/dns-query",
            trust = trust,
            timeoutMs = 1_000,
            clock = { now }
        )

        assertTrue(resolver.isAvailable())
        runCatching { resolver.query("cloudflare.com") }
        assertFalse(resolver.isAvailable())

        now += 60_000
        assertTrue(resolver.isAvailable())
    }

    private fun resolverFor(port: Int) = TrustedResolver(
        name = "test",
        endpoint = "https://127.0.0.1:$port/dns-query",
        trust = trust,
        timeoutMs = 5_000
    )

    private fun resource(path: String) =
        checkNotNull(javaClass.classLoader?.getResourceAsStream(path)) { "missing fixture $path" }

    private fun tlsServer(keystore: String, status: String): TlsServer =
        TlsServer(tlsServerSocket(keystore), Behavior.RESPOND, status, dnsResponse)
            .also { closeables += it }

    private fun stallingTlsServer(keystore: String): TlsServer =
        TlsServer(tlsServerSocket(keystore), Behavior.CLOSE_AFTER_HANDSHAKE, "", ByteArray(0))
            .also { closeables += it }

    private fun abortingServer(): TlsServer =
        TlsServer(
            ServerSocket(0, 4, InetAddress.getByName("127.0.0.1")),
            Behavior.CLOSE_ON_ACCEPT,
            "",
            ByteArray(0)
        ).also { closeables += it }

    private fun tlsServerSocket(keystore: String): ServerSocket {
        val store = KeyStore.getInstance("PKCS12")
        resource(keystore).use { store.load(it, passphrase) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(store, passphrase)
        val context = SSLContext.getInstance("TLS")
        context.init(kmf.keyManagers, null, null)
        return context.serverSocketFactory
            .createServerSocket(0, 4, InetAddress.getByName("127.0.0.1"))
    }

    private enum class Behavior { RESPOND, CLOSE_AFTER_HANDSHAKE, CLOSE_ON_ACCEPT }

    private class TlsServer(
        private val server: ServerSocket,
        private val behavior: Behavior,
        private val status: String,
        private val body: ByteArray
    ) : Closeable {

        val port: Int get() = server.localPort

        init {
            Thread(::serve, "TlsServer-$port").apply { isDaemon = true }.start()
        }

        private fun serve() {
            while (!server.isClosed) {
                val socket = try {
                    server.accept()
                } catch (_: IOException) {
                    return
                }
                try {
                    socket.use {
                        when (behavior) {
                            Behavior.RESPOND -> respond(it)
                            // Reading the request drives the handshake to completion, so the
                            // client fails only after it has validated the chain.
                            Behavior.CLOSE_AFTER_HANDSHAKE -> readRequest(it.getInputStream())
                            Behavior.CLOSE_ON_ACCEPT -> Unit
                        }
                    }
                } catch (_: IOException) {
                    // A rejected handshake surfaces here; keep serving later connections.
                }
            }
        }

        private fun respond(socket: Socket) {
            readRequest(socket.getInputStream())
            val header = "HTTP/1.1 $status\r\n" +
                "Content-Type: application/dns-message\r\n" +
                "Content-Length: ${body.size}\r\n" +
                "Connection: close\r\n\r\n"
            socket.getOutputStream().apply {
                write(header.toByteArray(Charsets.US_ASCII))
                write(body)
                flush()
            }
        }

        private fun readRequest(input: java.io.InputStream) {
            var contentLength = 0
            var line = readLine(input)
            while (line.isNotEmpty()) {
                if (line.startsWith("Content-Length:", ignoreCase = true)) {
                    contentLength = line.substringAfter(':').trim().toInt()
                }
                line = readLine(input)
            }
            var read = 0
            while (read < contentLength) {
                val n = input.read(ByteArray(contentLength - read))
                if (n < 0) break
                read += n
            }
        }

        private fun readLine(input: java.io.InputStream): String {
            val builder = StringBuilder()
            while (true) {
                val c = input.read()
                if (c < 0) break
                if (c == '\n'.code) break
                if (c != '\r'.code) builder.append(c.toChar())
            }
            return builder.toString()
        }

        override fun close() {
            server.close()
        }
    }
}
