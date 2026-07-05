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

import android.util.Base64
import okhttp3.Cookie
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import javax.crypto.KeyGenerator

/**
 * Off-device there is no AndroidKeyStore, so [SecureCookieJar]'s `secretKey` is null and
 * the jar fails closed on every cookie. Here we reflect the private field and seed it with
 * a throwaway in-memory software AES-256 key so the real Cipher, framing, and jar logic
 * run unmodified on the host under Robolectric.
 */
@RunWith(RobolectricTestRunner::class)
class SecureCookieJarTest {

    private lateinit var storage: InMemoryCookieStorage
    private lateinit var jar: SecureCookieJar

    @Before
    fun setUp() {
        storage = InMemoryCookieStorage()
        jar = SecureCookieJar(storage)

        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val field = SecureCookieJar::class.java.getDeclaredField("secretKey")
        field.isAccessible = true
        field.set(jar, key)
    }

    private fun cookie(
        name: String,
        value: String,
        domain: String,
        path: String = "/",
        expiresAt: Long,
    ): Cookie = Cookie.Builder()
        .name(name)
        .value(value)
        .domain(domain)
        .path(path)
        .expiresAt(expiresAt)
        .build()

    private fun url(spec: String): HttpUrl = spec.toHttpUrl()

    @Test
    fun roundTripReturnsSavedCookies() {
        val future = System.currentTimeMillis() + 60_000L
        val cookie = cookie("session", "A", domain = "example.com", expiresAt = future)
        val target = url("https://example.com/")

        jar.saveFromResponse(target, listOf(cookie))
        val loaded = jar.loadForRequest(target)

        assertTrue(loaded.any { it.name == "session" && it.value == "A" })
    }

    @Test
    fun expiredCookieNotReturned() {
        val past = System.currentTimeMillis() - 60_000L
        val cookie = cookie("session", "A", domain = "example.com", expiresAt = past)
        val target = url("https://example.com/")

        jar.saveFromResponse(target, listOf(cookie))

        assertTrue(jar.loadForRequest(target).isEmpty())
    }

    @Test
    fun expiredOverwritePrunesDomain() {
        val future = System.currentTimeMillis() + 60_000L
        val past = System.currentTimeMillis() - 60_000L
        val target = url("https://example.com/")

        jar.saveFromResponse(target, listOf(cookie("session", "A", domain = "example.com", expiresAt = future)))
        assertTrue(jar.loadForRequest(target).any { it.name == "session" })

        jar.saveFromResponse(target, listOf(cookie("session", "B", domain = "example.com", expiresAt = past)))

        assertTrue(jar.loadForRequest(target).isEmpty())
        assertNull(storage.getStringSet("cookies_example.com", null))
    }

    @Test
    fun cookiesScopedByDomain() {
        val future = System.currentTimeMillis() + 60_000L
        val cookie = cookie("session", "A", domain = "a.example.com", expiresAt = future)
        val saveTarget = url("https://a.example.com/")

        jar.saveFromResponse(saveTarget, listOf(cookie))

        assertTrue(jar.loadForRequest(url("https://b.example.com/")).isEmpty())
        assertTrue(jar.loadForRequest(url("https://a.example.com/")).any { it.name == "session" })
    }

    @Test
    fun cookiesScopedByPath() {
        val future = System.currentTimeMillis() + 60_000L
        val cookie = cookie("session", "A", domain = "example.com", path = "/admin", expiresAt = future)
        val saveTarget = url("https://example.com/admin")

        jar.saveFromResponse(saveTarget, listOf(cookie))

        assertTrue(jar.loadForRequest(url("https://example.com/admin/x")).any { it.name == "session" })
        assertTrue(jar.loadForRequest(url("https://example.com/other")).isEmpty())
    }

    @Test
    fun overwriteInvalidatesCache() {
        val future = System.currentTimeMillis() + 60_000L
        val target = url("https://example.com/")

        jar.saveFromResponse(target, listOf(cookie("session", "A", domain = "example.com", expiresAt = future)))
        assertEquals("A", jar.loadForRequest(target).single { it.name == "session" }.value)

        jar.saveFromResponse(target, listOf(cookie("session", "B", domain = "example.com", expiresAt = future)))
        assertEquals("B", jar.loadForRequest(target).single { it.name == "session" }.value)
    }

    @Test
    fun corruptStoredValueDroppedFailClosed() {
        storage.putStringSet("cookies_example.com", setOf("!!!not-valid-ciphertext!!!"))
        storage.putStringSet("_cookie_domains", setOf("example.com"))

        assertTrue(jar.loadForRequest(url("https://example.com/")).isEmpty())
    }

    @Test
    fun framingUsesVersionByte() {
        val future = System.currentTimeMillis() + 60_000L
        val cookie = cookie("session", "A", domain = "example.com", expiresAt = future)
        val target = url("https://example.com/")

        jar.saveFromResponse(target, listOf(cookie))

        val stored = storage.getStringSet("cookies_example.com", null)!!.single()
        val raw = Base64.decode(stored, Base64.NO_WRAP)

        assertEquals(1, raw[0].toInt())
    }
}
