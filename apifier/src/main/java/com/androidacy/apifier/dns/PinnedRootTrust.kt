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

import android.content.Context
import com.androidacy.apifier.R
import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * TLS material that trusts the bundled resolver roots and nothing else, so a CA relocated into
 * the system store cannot make an intercepted resolver look genuine.
 *
 * There is no fallback anywhere in this class. A failure to load or initialize throws out of the
 * constructor, because a check that quietly degrades to the platform trust store would report
 * trust it never established.
 */
class PinnedRootTrust(roots: List<X509Certificate>) {

    /**
     * True once the current thread has entered certificate validation for the connection it is
     * driving. It separates a resolver that presented a certificate we rejected from one that
     * never completed a connection, which the exception type alone cannot distinguish. Queries
     * run concurrently on a shared executor and each connection holds one thread for its
     * lifetime, so the flag is per thread rather than per instance.
     */
    val certificatePresented: ThreadLocal<Boolean> = ThreadLocal.withInitial { false }

    val trustManager: X509TrustManager

    val socketFactory: SSLSocketFactory

    /** Matches the dialed IP literal against the leaf's `iPAddress` SAN entries. */
    val hostnameVerifier: HostnameVerifier = HostnameVerifier { host, session -> coversAddress(host, session) }

    init {
        require(roots.isNotEmpty()) { "PinnedRootTrust requires at least one root certificate" }

        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
        roots.forEachIndexed { index, root -> store.setCertificateEntry("resolver-root-$index", root) }

        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(store)
        val delegate = factory.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
            ?: throw IllegalStateException("No X509TrustManager for the pinned resolver roots")

        trustManager = RecordingTrustManager(delegate, certificatePresented)
        socketFactory = SSLContext.getInstance("TLS")
            .apply { init(null, arrayOf(trustManager), null) }
            .socketFactory
    }

    private fun coversAddress(host: String, session: SSLSession): Boolean {
        val dialed = host.removeSurrounding("[", "]")
        if (!AddressClassifier.isIpLiteral(dialed)) return false
        val expected = runCatching { InetAddress.getByName(dialed).address }.getOrNull() ?: return false
        val leaf = session.peerCertificates.firstOrNull() as? X509Certificate ?: return false
        val names = runCatching { leaf.subjectAlternativeNames }.getOrNull() ?: return false
        return names.any { entry ->
            entry.size >= 2 && entry[0] == SAN_IP_ADDRESS &&
                runCatching { InetAddress.getByName(entry[1] as String).address }.getOrNull()
                    ?.contentEquals(expected) == true
        }
    }

    private class RecordingTrustManager(
        private val delegate: X509TrustManager,
        private val presented: ThreadLocal<Boolean>
    ) : X509TrustManager by delegate {

        override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
            presented.set(true)
            delegate.checkServerTrusted(chain, authType)
        }
    }

    companion object {

        private const val SAN_IP_ADDRESS = 7

        /** Loads the roots bundled as `R.raw.apifier_resolver_roots`. */
        fun load(context: Context): PinnedRootTrust {
            val pem = context.resources.openRawResource(R.raw.apifier_resolver_roots)
                .bufferedReader()
                .use { it.readText() }
            return PinnedRootTrust(parsePem(pem))
        }

        /** Parses every certificate block out of a concatenated PEM bundle. */
        fun parsePem(pem: String): List<X509Certificate> {
            val factory = CertificateFactory.getInstance("X.509")
            return PEM_BLOCK.findAll(pem).map { match ->
                factory.generateCertificate(
                    ByteArrayInputStream(match.value.toByteArray(Charsets.US_ASCII))
                ) as X509Certificate
            }.toList()
        }

        private val PEM_BLOCK =
            Regex("-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", RegexOption.DOT_MATCHES_ALL)
    }
}
