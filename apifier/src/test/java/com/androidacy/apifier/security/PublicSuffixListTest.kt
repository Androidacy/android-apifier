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
package com.androidacy.apifier.security

import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PublicSuffixListTest {

    @Test
    fun exactRuleMatches() {
        val psl = PublicSuffixList(sequenceOf("com"))

        assertTrue(psl.isPublicSuffix("com"))
        assertFalse(psl.isPublicSuffix("example.com"))
        assertEquals("example.com", psl.effectiveTldPlusOne("a.b.example.com"))
    }

    @Test
    fun wildcardRuleMatches() {
        val psl = PublicSuffixList(sequenceOf("*.ck"))

        assertTrue(psl.isPublicSuffix("anything.ck"))
        assertEquals("a.anything.ck", psl.effectiveTldPlusOne("a.anything.ck"))
    }

    @Test
    fun exceptionBeatsWildcard() {
        val psl = PublicSuffixList(sequenceOf("*.ck", "!www.ck"))

        assertFalse(psl.isPublicSuffix("www.ck"))
        assertEquals("www.ck", psl.effectiveTldPlusOne("www.ck"))
    }

    @Test
    fun exceptionBeatsLongerRule() {
        // "a.b.ck" (3 labels) matches longer than "!b.ck" (2 labels); the exception must
        // still win, not the longer exact rule.
        val psl = PublicSuffixList(sequenceOf("a.b.ck", "!b.ck"))

        assertFalse(psl.isPublicSuffix("a.b.ck"))
        assertEquals("b.ck", psl.effectiveTldPlusOne("a.b.ck"))
    }

    @Test
    fun unknownTldUsesImplicitStar() {
        val psl = PublicSuffixList(sequenceOf("com"))

        assertTrue(psl.isPublicSuffix("unknowntld"))
        assertEquals("foo.unknowntld", psl.effectiveTldPlusOne("foo.unknowntld"))
    }

    @Test
    fun publicSuffixItselfHasNoEtldPlusOne() {
        val psl = PublicSuffixList(sequenceOf("com", "*.ck"))

        assertNull(psl.effectiveTldPlusOne("com"))
        assertNull(psl.effectiveTldPlusOne("ck"))
    }

    @Test
    fun unicodeDomainNormalized() {
        // xn--p1ai is the punycode form of the Cyrillic "рф" TLD label.
        val psl = PublicSuffixList(sequenceOf("xn--p1ai"))

        assertTrue(psl.isPublicSuffix("xn--p1ai"))
        assertTrue(psl.isPublicSuffix("рф"))
        assertEquals("example.xn--p1ai", psl.effectiveTldPlusOne("example.рф"))
    }

    @Test
    fun ipLiteralNeverMatches() {
        val psl = PublicSuffixList(sequenceOf("4"))

        assertFalse(psl.isPublicSuffix("1.2.3.4"))
        assertNull(psl.effectiveTldPlusOne("1.2.3.4"))
        assertFalse(psl.isPublicSuffix("[::1]"))
        assertNull(psl.effectiveTldPlusOne("[::1]"))
    }

    @Test
    fun trailingDotNormalizedAwaySameAsDotless() {
        val psl = PublicSuffixList(sequenceOf("com"))

        assertNull(psl.effectiveTldPlusOne("com."))
        assertEquals("example.com", psl.effectiveTldPlusOne("example.com."))
    }

    @Test
    fun ipLiteralWithTrailingDotStillRejected() {
        val psl = PublicSuffixList(sequenceOf("4"))

        assertFalse(psl.isPublicSuffix("1.2.3.4."))
        assertNull(psl.effectiveTldPlusOne("1.2.3.4."))
    }

    @Test
    fun bundledListLoadsAndCoversKnownSuffixes() {
        val psl = PublicSuffixList.load(ApplicationProvider.getApplicationContext())

        assertTrue(psl.isPublicSuffix("co.uk"))
        assertTrue(psl.isPublicSuffix("github.io"))
    }
}
