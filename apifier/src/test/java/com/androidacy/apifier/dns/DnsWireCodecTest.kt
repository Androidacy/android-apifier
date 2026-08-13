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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The fixture is one real RFC 8484 response captured from 1.1.1.1 for `cloudflare.com` A,
 * carrying two answer records reached through a compression pointer.
 */
class DnsWireCodecTest {

    private val fixture: ByteArray =
        checkNotNull(javaClass.classLoader?.getResourceAsStream("dns/cloudflare_com_a_response.bin"))
            .use { it.readBytes() }

    @Test
    fun wireQueryStructure() {
        val result = DnsWireCodec.buildQuery("example.com", 1)

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
    fun parsesFixtureAddresses() {
        val answer = DnsWireCodec.parseResponse(fixture)

        assertEquals(listOf("104.16.132.229", "104.16.133.229"), answer.addresses)
        assertTrue(answer.minTtlSeconds >= 0)
    }

    @Test
    fun parseCategorizesFailures() {
        val nxdomain = fixture.copyOf()
        nxdomain[3] = ((nxdomain[3].toInt() and 0xF0) or 0x03).toByte()
        assertEquals(
            DnsParseException.Kind.NXDOMAIN,
            assertThrows(DnsParseException::class.java) { DnsWireCodec.parseResponse(nxdomain) }.kind
        )

        val servfail = fixture.copyOf()
        servfail[3] = ((servfail[3].toInt() and 0xF0) or 0x02).toByte()
        assertEquals(
            DnsParseException.Kind.SERVER_ERROR,
            assertThrows(DnsParseException::class.java) { DnsWireCodec.parseResponse(servfail) }.kind
        )

        assertEquals(
            DnsParseException.Kind.INVALID,
            assertThrows(DnsParseException::class.java) {
                DnsWireCodec.parseResponse(fixture.copyOfRange(0, 8))
            }.kind
        )
    }

    @Test
    fun truncatedBodyIsInvalid() {
        assertEquals(
            DnsParseException.Kind.INVALID,
            assertThrows(DnsParseException::class.java) {
                DnsWireCodec.parseResponse(fixture.copyOfRange(0, 12))
            }.kind
        )
        assertEquals(
            DnsParseException.Kind.INVALID,
            assertThrows(DnsParseException::class.java) {
                DnsWireCodec.parseResponse(fixture.copyOfRange(0, 40))
            }.kind
        )
    }

    @Test
    fun noerrorWithoutRecordsIsEmptyAnswer() {
        val nodata = fixture.copyOf()
        nodata[6] = 0
        nodata[7] = 0

        assertEquals(emptyList<String>(), DnsWireCodec.parseResponse(nodata).addresses)
    }

    @Test
    fun parseReturnsUnfilteredAddresses() {
        val private = fixture.copyOf()
        val rdata = indexOfFirstAnswerRdata(private)
        private[rdata] = 10
        private[rdata + 1] = 0
        private[rdata + 2] = 0
        private[rdata + 3] = 1

        assertTrue("10.0.0.1" in DnsWireCodec.parseResponse(private).addresses)
    }

    /** Offset of the first A record's four rdata bytes, located by its captured value. */
    private fun indexOfFirstAnswerRdata(data: ByteArray): Int {
        val needle = byteArrayOf(104.toByte(), 16, 132.toByte(), 229.toByte())
        for (i in 0..data.size - needle.size) {
            if (needle.indices.all { data[i + it] == needle[it] }) return i
        }
        throw AssertionError("fixture no longer contains 104.16.132.229")
    }
}
