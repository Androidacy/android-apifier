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
