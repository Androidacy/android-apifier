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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AddressClassifierTest {

    @Test
    fun classifiesEveryCategory() {
        assertEquals(AddressCategory.PUBLIC, AddressClassifier.classify("8.8.8.8"))
        assertEquals(AddressCategory.PUBLIC, AddressClassifier.classify("2606:4700:4700::1111"))
        assertEquals(AddressCategory.LOOPBACK, AddressClassifier.classify("127.0.0.1"))
        assertEquals(AddressCategory.LOOPBACK, AddressClassifier.classify("::1"))
        assertEquals(AddressCategory.UNSPECIFIED, AddressClassifier.classify("0.0.0.0"))
        assertEquals(AddressCategory.UNSPECIFIED, AddressClassifier.classify("::"))
        assertEquals(AddressCategory.PRIVATE, AddressClassifier.classify("10.0.0.1"))
        assertEquals(AddressCategory.PRIVATE, AddressClassifier.classify("192.168.1.1"))
        assertEquals(AddressCategory.PRIVATE, AddressClassifier.classify("172.16.0.1"))
        assertEquals(AddressCategory.LINK_LOCAL, AddressClassifier.classify("169.254.1.1"))
        assertEquals(AddressCategory.LINK_LOCAL, AddressClassifier.classify("fe80::1"))
        assertEquals(AddressCategory.MULTICAST, AddressClassifier.classify("224.0.0.1"))
        assertEquals(AddressCategory.MULTICAST, AddressClassifier.classify("ff02::1"))
    }

    @Test
    fun classifiesCgnatAndUlaRangesAndTheirBoundaries() {
        assertEquals(AddressCategory.CGNAT, AddressClassifier.classify("100.64.0.1"))
        assertEquals(AddressCategory.CGNAT, AddressClassifier.classify("100.127.255.255"))
        assertEquals(AddressCategory.PUBLIC, AddressClassifier.classify("100.63.255.255"))
        assertEquals(AddressCategory.PUBLIC, AddressClassifier.classify("100.128.0.1"))
        assertEquals(AddressCategory.ULA, AddressClassifier.classify("fd00::1"))
        assertEquals(AddressCategory.ULA, AddressClassifier.classify("fc00::1"))
    }

    @Test
    fun unparseableIsInvalid() {
        assertEquals(AddressCategory.INVALID, AddressClassifier.classify(""))
        assertEquals(AddressCategory.INVALID, AddressClassifier.classify("999.1.1.1"))
        assertEquals(AddressCategory.INVALID, AddressClassifier.classify("1.2.3"))
        assertEquals(AddressCategory.INVALID, AddressClassifier.classify("example.com"))
        assertEquals(AddressCategory.INVALID, AddressClassifier.classify("fe80::zz"))
    }

    @Test
    fun ipLiteralAcceptsBracketedIpv6() {
        assertTrue(AddressClassifier.isIpLiteral("[2606:4700::1111]"))
        assertTrue(AddressClassifier.isIpLiteral("2606:4700::1111"))
        assertTrue(AddressClassifier.isIpLiteral("1.1.1.1"))
        assertFalse(AddressClassifier.isIpLiteral("example.com"))
    }

    @Test
    fun safeHostnameRejectsShellPunctuation() {
        assertTrue(AddressClassifier.isSafeHostname("api.example.com"))
        assertTrue(AddressClassifier.isSafeHostname("a-b_c.example"))
        assertFalse(AddressClassifier.isSafeHostname("evil host!"))
        assertFalse(AddressClassifier.isSafeHostname("example.com/path"))
        assertFalse(AddressClassifier.isSafeHostname(""))
    }

    @Test
    fun safeHostnameRejectsEmptyAndOverlongLabels() {
        assertFalse("a trailing dot leaves an empty label", AddressClassifier.isSafeHostname("example.com."))
        assertFalse(AddressClassifier.isSafeHostname(".example.com"))
        assertFalse(AddressClassifier.isSafeHostname("a..b"))
        assertFalse(AddressClassifier.isSafeHostname("${"a".repeat(64)}.example.com"))
    }
}
