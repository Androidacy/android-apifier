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
package com.androidacy.apifier.http

import android.net.Uri
import com.androidacy.apifier.security.PublicSuffixList
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.Calendar
import java.util.TimeZone

@RunWith(RobolectricTestRunner::class)
class CookieTest {

    private val psl = PublicSuffixList(sequenceOf("com", "github.io"))

    @Test
    fun parsesBasicNameValueWithDefaults() {
        val cookie = Cookie.parse(Uri.parse("https://a.example.com/x/y"), "sid=abc", psl)!!

        assertEquals("sid", cookie.name)
        assertEquals("abc", cookie.value)
        assertTrue(cookie.hostOnly)
        assertEquals("a.example.com", cookie.domain)
        assertEquals("/x", cookie.path)
        assertEquals(Long.MAX_VALUE, cookie.expiresAt)
    }

    @Test
    fun maxAgeBeatsExpires() {
        val cookie = Cookie.parse(
            Uri.parse("https://example.com/"),
            "sid=abc; Max-Age=3600; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
            psl,
        )!!

        // Expires alone names a 2015 instant, well in the past; only Max-Age winning
        // pushes expiresAt into the future.
        assertTrue(cookie.expiresAt > System.currentTimeMillis())
    }

    @Test
    fun legacyExpiresFormatsAccepted() {
        val uri = Uri.parse("https://example.com/")
        val rfc1123 = Cookie.parse(uri, "sid=a; Expires=Wed, 21 Oct 2015 07:28:00 GMT", psl)!!
        val rfc850 = Cookie.parse(uri, "sid=a; Expires=Wednesday, 21-Oct-15 07:28:00 GMT", psl)!!
        val asctime = Cookie.parse(uri, "sid=a; Expires=Wed Oct 21 07:28:00 2015", psl)!!

        assertEquals(rfc1123.expiresAt, rfc850.expiresAt)
        assertEquals(rfc1123.expiresAt, asctime.expiresAt)
    }

    @Test
    fun twoDigitYearNormalized() {
        val uri = Uri.parse("https://example.com/")
        val y70 = Cookie.parse(uri, "sid=a; Expires=Mon, 01-Jan-70 00:00:00 GMT", psl)!!
        val y69 = Cookie.parse(uri, "sid=a; Expires=Fri, 01-Jan-69 00:00:00 GMT", psl)!!

        assertEquals(1970, yearOf(y70.expiresAt))
        assertEquals(2069, yearOf(y69.expiresAt))
    }

    @Test
    fun aCookieWithNoExpiryIsNotPersistent() {
        val cookie = Cookie.parse(Uri.parse("https://example.com/"), "sid=abc", psl)!!

        assertFalse(cookie.persistent)
    }

    @Test
    fun aCookieWithMaxAgeIsPersistent() {
        val cookie = Cookie.parse(Uri.parse("https://example.com/"), "sid=abc; Max-Age=3600", psl)!!

        assertTrue(cookie.persistent)
    }

    @Test
    fun aCookieWithExpiresIsPersistent() {
        val cookie = Cookie.parse(
            Uri.parse("https://example.com/"),
            "sid=abc; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
            psl,
        )!!

        assertTrue(cookie.persistent)
    }

    @Test
    fun anUnparseableExpiresLeavesTheCookieNotPersistent() {
        val cookie = Cookie.parse(Uri.parse("https://example.com/"), "sid=abc; Expires=not-a-date", psl)!!

        assertFalse(cookie.persistent)
    }

    @Test
    fun domainAttributeMustMatchRequestHost() {
        val result = Cookie.parse(Uri.parse("https://example.com/"), "sid=a; Domain=other.com", psl)

        assertNull(result)
    }

    @Test
    fun publicSuffixDomainRejected() {
        val fromSubdomain = Cookie.parse(Uri.parse("https://a.github.io/"), "sid=a; Domain=github.io", psl)
        assertNull(fromSubdomain)

        val fromSuffixItself = Cookie.parse(Uri.parse("https://github.io/"), "sid=a; Domain=github.io", psl)!!
        assertTrue(fromSuffixItself.hostOnly)
        assertEquals("github.io", fromSuffixItself.domain)
    }

    @Test
    fun hostOnlyMatchesExactHostOnly() {
        val cookie = Cookie.Builder().name("sid").value("a").hostOnlyDomain("a.example.com").path("/").build()

        assertTrue(cookie.matches(Uri.parse("https://a.example.com/")))
        assertFalse(cookie.matches(Uri.parse("https://b.a.example.com/")))
    }

    @Test
    fun domainCookieMatchesSubdomainsWithBoundary() {
        val cookie = Cookie.Builder().name("sid").value("a").domain("example.com").path("/").build()

        assertTrue(cookie.matches(Uri.parse("https://a.example.com/")))
        assertFalse(cookie.matches(Uri.parse("https://notexample.com/")))
    }

    @Test
    fun pathMatchingHonorsBoundary() {
        val cookie = Cookie.Builder().name("sid").value("a").hostOnlyDomain("example.com").path("/admin").build()

        assertTrue(cookie.matches(Uri.parse("https://example.com/admin/x")))
        assertFalse(cookie.matches(Uri.parse("https://example.com/administrator")))
    }

    @Test
    fun rootPathCookieMatchesUrlWithNoPath() {
        val cookie = Cookie.Builder().name("sid").value("a").hostOnlyDomain("example.com").path("/").build()

        // Uri.getPath() returns "", not null, when the URL has no path segment.
        assertTrue(cookie.matches(Uri.parse("https://example.com")))
        assertTrue(cookie.matches(Uri.parse("https://example.com?q=1")))
    }

    @Test
    fun ipLiteralRequestHostRejectsSuffixDomain() {
        val suffixDomain = Cookie.parse(Uri.parse("https://192.168.1.1/"), "sid=a; Domain=168.1.1", psl)
        assertNull(suffixDomain)

        val exactDomain = Cookie.parse(Uri.parse("https://192.168.1.1/"), "sid=a; Domain=192.168.1.1", psl)!!
        assertTrue(exactDomain.hostOnly)
        assertEquals("192.168.1.1", exactDomain.domain)
    }

    private fun yearOf(epochMillis: Long): Int {
        val calendar = Calendar.getInstance(TimeZone.getTimeZone("GMT"))
        calendar.timeInMillis = epochMillis
        return calendar.get(Calendar.YEAR)
    }
}
