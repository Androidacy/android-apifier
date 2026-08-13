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

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.URL
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HttpsURLConnection

/** The resolver presented a certificate that failed pinned-root validation or SAN coverage. */
class CertificateRejectedException(message: String, cause: Throwable?) : IOException(message, cause)

/** The connection never completed, so the resolver has no opinion about this host. */
class ResolverUnavailableException(message: String, cause: Throwable?) : IOException(message, cause)

/**
 * One known-good public resolver, dialed by IP literal over RFC 8484 binary POST.
 *
 * The transport is deliberately [HttpsURLConnection] rather than the library's own call path:
 * the verdict this resolver feeds gates that path, and routing the check through it would let
 * the gate wait on itself.
 */
open class TrustedResolver(
    val name: String,
    private val endpoint: String,
    private val trust: PinnedRootTrust,
    private val timeoutMs: Int = DEFAULT_TIMEOUT_MS,
    private val clock: () -> Long = System::currentTimeMillis
) {

    private val consecutiveFailures = AtomicInteger(0)
    private val backoffUntilMillis = AtomicLong(0)

    /**
     * A and AAAA merged. An authoritative NXDOMAIN comes back as an empty answer, because the
     * verdict layer counts "answered: nothing" as a usable response and would otherwise score
     * it as a resolver that could not answer.
     */
    open fun query(hostname: String): DnsAnswer {
        val outcomes = listOf(DnsWireCodec.TYPE_A, DnsWireCodec.TYPE_AAAA).map { type ->
            try {
                Result.success(queryType(hostname, type))
            } catch (e: CertificateRejectedException) {
                recordFailure()
                throw e
            } catch (e: IOException) {
                Result.failure<DnsAnswer>(e)
            }
        }

        val answers = outcomes.mapNotNull { it.getOrNull() }
        if (answers.isEmpty()) {
            recordFailure()
            throw outcomes.first().exceptionOrNull() as IOException
        }

        recordSuccess()
        return DnsAnswer(
            answers.flatMap { it.addresses }.distinct(),
            answers.minOf { it.minTtlSeconds }
        )
    }

    /** False while this resolver is in failure backoff, capped at [MAX_BACKOFF_MS]. */
    open fun isAvailable(): Boolean = clock() >= backoffUntilMillis.get()

    private fun queryType(hostname: String, type: Int): DnsAnswer {
        val query = DnsWireCodec.buildQuery(hostname, type)
        trust.certificatePresented.set(false)
        val connection = URL(endpoint).openConnection() as HttpsURLConnection
        try {
            connection.sslSocketFactory = trust.socketFactory
            connection.hostnameVerifier = trust.hostnameVerifier
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("Content-Type", "application/dns-message")
            connection.setRequestProperty("Accept", "application/dns-message")
            // A pooled connection the resolver already closed fails at the write with no
            // handshake of its own, which would be read as a certificate rejection and block
            // every protected domain. One connection per query keeps that reading honest.
            connection.setRequestProperty("Connection", "close")
            connection.connectTimeout = timeoutMs
            connection.readTimeout = timeoutMs
            connection.doOutput = true

            connection.outputStream.use { it.write(query) }

            if (connection.responseCode != 200) {
                throw ResolverUnavailableException("$name answered HTTP ${connection.responseCode}", null)
            }
            return DnsWireCodec.parseResponse(
                connection.inputStream.use { readBounded(it, MAX_RESPONSE_BYTES) }
            )
        } catch (e: DnsParseException) {
            if (e.kind == DnsParseException.Kind.NXDOMAIN) return DnsAnswer(emptyList(), 0)
            throw e
        } catch (e: CertificateRejectedException) {
            throw e
        } catch (e: ResolverUnavailableException) {
            throw e
        } catch (e: IOException) {
            // Both cases arrive as SSLHandshakeException or a bare IOException, so the split
            // comes from what the trust manager recorded, not from the exception type.
            throw if (trust.certificatePresented.get() == true) {
                CertificateRejectedException("$name presented a rejected certificate", e)
            } else {
                ResolverUnavailableException("$name did not complete a connection", e)
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(stream: InputStream, maxBytes: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        var total = 0
        while (true) {
            val read = stream.read(buffer)
            if (read == -1) break
            total += read
            if (total > maxBytes) {
                throw DnsParseException(
                    DnsParseException.Kind.INVALID,
                    "DNS response exceeds $maxBytes bytes"
                )
            }
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }

    private fun recordFailure() {
        val failures = consecutiveFailures.updateAndGet { it.coerceAtMost(9) + 1 }
        val backoff = (1000L * (1 shl failures.coerceAtMost(5))).coerceAtMost(MAX_BACKOFF_MS)
        backoffUntilMillis.set(clock() + backoff)
    }

    private fun recordSuccess() {
        consecutiveFailures.set(0)
        backoffUntilMillis.set(0)
    }

    private companion object {
        const val DEFAULT_TIMEOUT_MS = 3000
        const val MAX_RESPONSE_BYTES = 65536
        const val MAX_BACKOFF_MS = 30_000L
    }
}
