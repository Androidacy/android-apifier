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

import androidx.test.core.app.ApplicationProvider
import com.androidacy.apifier.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.lang.reflect.Proxy
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLSession

@RunWith(RobolectricTestRunner::class)
class PinnedRootTrustTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private fun bundledRoots(): List<X509Certificate> {
        val pem = context.resources.openRawResource(R.raw.apifier_resolver_roots)
            .bufferedReader().use { it.readText() }
        return PinnedRootTrust.parsePem(pem)
    }

    @Test
    fun pinnedTrustAnchorsAreExactlyTheBundle() {
        val trust = PinnedRootTrust.load(context)

        assertEquals(
            bundledRoots().map { it.subjectX500Principal.name }.toSet(),
            trust.trustManager.acceptedIssuers.map { it.subjectX500Principal.name }.toSet()
        )
        assertEquals(bundledRoots().size, trust.trustManager.acceptedIssuers.size)
    }

    @Test
    fun pinnedTrustCoversAllThreeLiveRoots() {
        val subjects = bundledRoots().map { it.subjectX500Principal.name }

        assertTrue(subjects.any { it.contains("SSL.com Root Certification Authority ECC") })
        assertTrue(subjects.any { it.contains("GTS Root R1") })
        assertTrue(subjects.any { it.contains("USERTrust ECC Certification Authority") })
    }

    @Test
    fun pinnedTrustRejectsForeignChain() {
        val trust = PinnedRootTrust.load(context)

        assertThrows(CertificateException::class.java) {
            trust.trustManager.checkServerTrusted(leafChain("dns/test_selfsigned.p12"), "RSA")
        }
    }

    @Test
    fun hostnameVerifierRequiresIpSanCoverage() {
        val verifier = PinnedRootTrust.load(context).hostnameVerifier

        assertTrue(verifier.verify("127.0.0.1", sessionPresenting("dns/test_leaf_covering_localhost.p12")))
        assertFalse(verifier.verify("127.0.0.1", sessionPresenting("dns/test_leaf_wrong_san.p12")))
        assertFalse(verifier.verify("dns.example", sessionPresenting("dns/test_leaf_covering_localhost.p12")))
    }

    private fun leafChain(keystoreResource: String): Array<X509Certificate> {
        val keystore = KeyStore.getInstance("PKCS12")
        javaClass.classLoader!!.getResourceAsStream(keystoreResource)
            .use { keystore.load(it, "apifier-test".toCharArray()) }
        return keystore.getCertificateChain("leaf").map { it as X509Certificate }.toTypedArray()
    }

    /** An [SSLSession] that answers only [SSLSession.getPeerCertificates], which is all the verifier reads. */
    private fun sessionPresenting(keystoreResource: String): SSLSession {
        val chain: Array<Certificate> = leafChain(keystoreResource).toList().toTypedArray()
        return Proxy.newProxyInstance(
            javaClass.classLoader,
            arrayOf(SSLSession::class.java)
        ) { _, method, _ ->
            if (method.name == "getPeerCertificates") chain else null
        } as SSLSession
    }

    @Test
    fun constructionWithoutRootsFails() {
        assertThrows(IllegalArgumentException::class.java) { PinnedRootTrust(emptyList()) }
    }
}
