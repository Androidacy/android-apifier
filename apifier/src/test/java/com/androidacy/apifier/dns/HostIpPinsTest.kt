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

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HostIpPinsTest {

    @Test
    fun aPinnedHostResolvingOutsideItsPinsIsRefused() {
        val pins = pinsFor("api.example.com", "203.0.113.10")

        assertTrue(HostIpPins.refuses(pins, "api.example.com", listOf("203.0.113.99")))
    }

    @Test
    fun aPinnedHostResolvingInsideItsPinsProceeds() {
        val pins = pinsFor("api.example.com", "203.0.113.10")

        assertFalse(HostIpPins.refuses(pins, "api.example.com", listOf("203.0.113.10")))
    }

    @Test
    fun ipv6PinsCompareOnByteForm() {
        val pins = pinsFor("edge.example.com", "2606:4700:0000:0000:0000:0000:0000:1111")

        assertFalse(HostIpPins.refuses(pins, "edge.example.com", listOf("2606:4700::1111")))
    }

    @Test
    fun anUnpinnedHostIsUnaffectedByOtherHostsPins() {
        val pins = pinsFor("api.example.com", "203.0.113.10")

        assertFalse(HostIpPins.refuses(pins, "other.example.com", listOf("198.51.100.5")))
    }

    private fun pinsFor(domain: String, vararg addresses: String): Map<String, Set<String>> =
        HostIpPinsBuilder().apply { pin(domain, *addresses) }.build()
}
