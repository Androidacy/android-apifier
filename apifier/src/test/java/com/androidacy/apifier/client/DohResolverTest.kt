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

import android.util.Log
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.shadows.ShadowLog
import java.net.URL
import java.util.UUID
import javax.net.ssl.HttpsURLConnection

/**
 * Exercises [DohResolver] against live DoH providers — the real oracle for wire-format
 * correctness, since a hand-built fixture can't prove our parser agrees with what
 * providers actually emit. The constructor's IPv6 probe and Keystore load are one-time
 * costs, so a single resolver instance is shared across all tests in this class.
 *
 * [DohResolver.resolve] records a provider failure (with exponential backoff) whenever a
 * query comes back with no usable records — it doesn't distinguish a legitimate NXDOMAIN
 * from a real provider outage. With one resolver shared across the class, the NXDOMAIN
 * test would otherwise arm that backoff for every provider and starve whichever
 * live-resolution test runs next within the backoff window. Reset the per-provider health
 * map before each test so that real behavior, not JUnit's execution order, decides outcomes.
 */
@RunWith(RobolectricTestRunner::class)
class DohResolverTest {

    @Before
    fun resetProviderHealth() {
        val field = DohResolver::class.java.getDeclaredField("providerHealth")
        field.isAccessible = true
        (field.get(resolver) as MutableMap<*, *>).clear()
    }

    private fun isPublicAddress(ip: String): Boolean = invokePrivateClassifier("isPublicAddress", ip)
    private fun isValidIPv4(ip: String): Boolean = invokePrivateClassifier("isValidIPv4", ip)
    private fun isValidIPv6(ip: String): Boolean = invokePrivateClassifier("isValidIPv6", ip)

    private fun invokePrivateClassifier(name: String, ip: String): Boolean {
        val method = DohResolver::class.java.getDeclaredMethod(name, String::class.java)
        method.isAccessible = true
        return method.invoke(resolver, ip) as Boolean
    }

    // --- Reflection helpers for the private DohFailure classification core ---

    private fun dohFailureClass(): Class<*> =
        DohResolver::class.java.declaredClasses.first { it.simpleName == "DohFailure" }

    private fun dohQueryExceptionClass(): Class<*> =
        DohResolver::class.java.declaredClasses.first { it.simpleName == "DohQueryException" }

    private fun dohFailureValue(name: String): Any =
        dohFailureClass().enumConstants!!.first { (it as Enum<*>).name == name }

    private fun newDohQueryException(failureName: String, message: String): Throwable {
        val ctor = dohQueryExceptionClass().getDeclaredConstructor(dohFailureClass(), String::class.java)
        ctor.isAccessible = true
        return ctor.newInstance(dohFailureValue(failureName), message) as Throwable
    }

    private fun invokeMoreSignificant(a: Any?, b: Any?): String? {
        val method = DohResolver::class.java.getDeclaredMethod(
            "moreSignificant",
            dohFailureClass(),
            dohFailureClass()
        )
        method.isAccessible = true
        return (method.invoke(resolver, a, b) as? Enum<*>)?.name
    }

    private fun invokeClassifyThrowable(t: Throwable): String {
        val method = DohResolver::class.java.getDeclaredMethod("classifyThrowable", Throwable::class.java)
        method.isAccessible = true
        return (method.invoke(resolver, t) as Enum<*>).name
    }

    /** Reads the private `.failure` field off a caught [DohQueryException] instance. */
    private fun failureNameOf(e: Throwable): String {
        val field = e.javaClass.getDeclaredField("failure")
        field.isAccessible = true
        return (field.get(e) as Enum<*>).name
    }

    @Test
    fun moreSignificantOrdersByPrecedence() {
        val noDomain = dohFailureValue("NO_DOMAIN")
        val serverError = dohFailureValue("SERVER_ERROR")
        val networkError = dohFailureValue("NETWORK_ERROR")
        val invalidResponse = dohFailureValue("INVALID_RESPONSE")

        assertEquals("NO_DOMAIN", invokeMoreSignificant(networkError, noDomain))
        assertEquals("SERVER_ERROR", invokeMoreSignificant(serverError, invalidResponse))
        assertEquals("INVALID_RESPONSE", invokeMoreSignificant(invalidResponse, networkError))
        assertEquals("NO_DOMAIN", invokeMoreSignificant(serverError, noDomain))
        assertEquals("SERVER_ERROR", invokeMoreSignificant(null, serverError))
        assertNull(invokeMoreSignificant(null, null))
    }

    @Test
    fun classifyThrowableMapsByType() {
        assertEquals("NETWORK_ERROR", invokeClassifyThrowable(java.net.SocketTimeoutException("timeout")))
        assertEquals("NETWORK_ERROR", invokeClassifyThrowable(java.net.ConnectException("refused")))
        assertEquals("NETWORK_ERROR", invokeClassifyThrowable(javax.net.ssl.SSLException("tls failure")))
        assertEquals("NETWORK_ERROR", invokeClassifyThrowable(java.net.UnknownHostException("nope")))
        assertEquals("NETWORK_ERROR", invokeClassifyThrowable(java.io.IOException("io")))
        assertEquals("INVALID_RESPONSE", invokeClassifyThrowable(RuntimeException("boom")))
        assertEquals("SERVER_ERROR", invokeClassifyThrowable(newDohQueryException("SERVER_ERROR", "x")))
    }

    @Test
    fun parseDnsWireResponseCategorizesCorruptedBytes() {
        val query = resolver.buildDnsWireQuery("cloudflare.com", 1)
        val responseBytes = postDnsWireQuery(query)

        val nxdomainBytes = responseBytes.copyOf()
        nxdomainBytes[3] = ((nxdomainBytes[3].toInt() and 0xF0) or 0x03).toByte()
        val nxEx = assertThrows(Exception::class.java) {
            resolver.parseDnsWireResponse("cloudflare.com", nxdomainBytes, 1)
        }
        assertEquals("NO_DOMAIN", failureNameOf(nxEx))

        val servfailBytes = responseBytes.copyOf()
        servfailBytes[3] = ((servfailBytes[3].toInt() and 0xF0) or 0x02).toByte()
        val servfailEx = assertThrows(Exception::class.java) {
            resolver.parseDnsWireResponse("cloudflare.com", servfailBytes, 1)
        }
        assertEquals("SERVER_ERROR", failureNameOf(servfailEx))

        val tooShort = responseBytes.copyOfRange(0, 8)
        val shortEx = assertThrows(Exception::class.java) {
            resolver.parseDnsWireResponse("cloudflare.com", tooShort, 1)
        }
        assertEquals("INVALID_RESPONSE", failureNameOf(shortEx))
    }

    @Test
    fun nxdomainLogsNoDomainReason() {
        ShadowLog.clear()

        // Live successful resolution first: proves providers are reachable, and
        // must not itself trigger the give-up WARN (cache-hit / success path).
        val liveAddresses = resolver.resolve("cloudflare.com")
        assertNotNull("expected a live resolution for cloudflare.com", liveAddresses)
        assertTrue(liveAddresses!!.isNotEmpty())
        assertTrue(
            "a successful resolution must not log the DoH give-up WARN",
            ShadowLog.getLogs().none { it.type == Log.WARN && it.tag == "DohResolver" }
        )

        // isIpAddress early return must not log the WARN either.
        ShadowLog.clear()
        assertNull(resolver.resolve("192.0.2.1"))
        assertTrue(
            "the isIpAddress early return must not log the DoH give-up WARN",
            ShadowLog.getLogs().none { it.type == Log.WARN && it.tag == "DohResolver" }
        )

        ShadowLog.clear()
        val randomLabel = UUID.randomUUID().toString().replace("-", "")
        val hostname = "nx-$randomLabel.cloudflare.com"

        assertNull(resolver.resolve(hostname))

        val warnLog = ShadowLog.getLogs().firstOrNull {
            it.type == Log.WARN && it.tag == "DohResolver" &&
                it.msg?.contains(hostname) == true && it.msg?.contains("NO_DOMAIN") == true
        }
        assertNotNull("expected a WARN log with NO_DOMAIN for $hostname", warnLog)
    }

    @Test
    fun resolvesRealHostnameToPublicIps() {
        val addresses = resolver.resolve("cloudflare.com")

        assertNotNull("expected a live resolution for cloudflare.com", addresses)
        assertTrue(addresses!!.isNotEmpty())
        addresses.forEach { ip ->
            assertTrue("$ip should be syntactically valid and not private/loopback", isPublicAddress(ip))
        }
    }

    @Test
    fun resolvesNxdomainToNull() {
        // Prove providers are actually reachable first, so the null asserted below means
        // NXDOMAIN and not "every provider was unreachable" — resolve() can't tell those
        // apart on its own, and a no-egress runner would otherwise pass this test for the
        // wrong reason.
        val liveAddresses = resolver.resolve("cloudflare.com")
        assertNotNull("expected a live resolution for cloudflare.com", liveAddresses)
        assertTrue(liveAddresses!!.isNotEmpty())

        val randomLabel = UUID.randomUUID().toString().replace("-", "")
        val hostname = "nx-$randomLabel.cloudflare.com"

        assertNull(resolver.resolve(hostname))
    }

    @Test
    fun buildDnsWireQueryStructure() {
        val result = resolver.buildDnsWireQuery("example.com", 1)

        assertEquals(0, result[0].toInt())
        assertEquals(0, result[1].toInt())
        assertEquals(0x01, result[2].toInt())
        assertEquals(0x00, result[3].toInt())
        assertEquals(0, result[4].toInt())
        assertEquals(1, result[5].toInt())
        assertEquals(0, result[10].toInt())
        assertEquals(1, result[11].toInt())

        assertEquals(7, result[12].toInt())
        val exampleLabel = "example".toByteArray(Charsets.US_ASCII)
        for (i in exampleLabel.indices) {
            assertEquals(exampleLabel[i], result[13 + i])
        }
        assertEquals(3, result[20].toInt())
        val comLabel = "com".toByteArray(Charsets.US_ASCII)
        for (i in comLabel.indices) {
            assertEquals(comLabel[i], result[21 + i])
        }
        assertEquals(0, result[24].toInt())

        assertEquals(0, result.size % 128)
    }

    @Test
    fun parsesRealResponseThenHandlesTruncation() {
        val query = resolver.buildDnsWireQuery("cloudflare.com", 1)
        val responseBytes = postDnsWireQuery(query)

        val record = resolver.parseDnsWireResponse("cloudflare.com", responseBytes, 1)
        assertTrue(record.addresses.isNotEmpty())
        record.addresses.forEach { ip -> assertTrue("$ip should be a public IPv4 address", isValidIPv4(ip)) }

        val belowHeader = responseBytes.copyOfRange(0, 8)
        assertThrows(Exception::class.java) {
            resolver.parseDnsWireResponse("cloudflare.com", belowHeader, 1)
        }

        val headerOnly = responseBytes.copyOfRange(0, 12)
        assertThrows(Exception::class.java) {
            resolver.parseDnsWireResponse("cloudflare.com", headerOnly, 1)
        }
    }

    private fun postDnsWireQuery(query: ByteArray): ByteArray {
        val conn = URL("https://1.1.1.1/dns-query").openConnection() as HttpsURLConnection
        try {
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/dns-message")
            conn.setRequestProperty("Accept", "application/dns-message")
            conn.connectTimeout = 10_000
            conn.readTimeout = 10_000
            conn.doOutput = true
            conn.outputStream.use { it.write(query) }

            assertEquals(200, conn.responseCode)
            return conn.inputStream.use { it.readBytes() }
        } finally {
            conn.disconnect()
        }
    }

    @Test
    fun privateAddressesRejectedByClassifier() {
        assertFalse(isPublicAddress("10.0.0.1"))
        assertFalse(isPublicAddress("127.0.0.1"))
        assertFalse(isPublicAddress("169.254.1.1"))
        assertFalse(isPublicAddress("::1"))
        assertFalse(isPublicAddress("fe80::1"))
        assertFalse(isPublicAddress("224.0.0.1"))
        assertTrue(isPublicAddress("8.8.8.8"))
        assertTrue(isPublicAddress("1.1.1.1"))
        assertTrue(isPublicAddress("2606:4700:4700::1111"))

        assertTrue(isValidIPv4("8.8.8.8"))
        assertFalse(isValidIPv4("2606:4700:4700::1111"))
        assertTrue(isValidIPv6("2606:4700:4700::1111"))
        assertFalse(isValidIPv6("8.8.8.8"))
    }

    companion object {
        private val resolver: DohResolver by lazy { DohResolver(DohConfig()) }
    }
}
