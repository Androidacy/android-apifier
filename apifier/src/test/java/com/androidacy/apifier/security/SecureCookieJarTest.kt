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

import android.net.Uri
import android.util.Base64
import com.androidacy.apifier.http.Cookie
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
        persistent: Boolean = true,
    ): Cookie = Cookie.Builder()
        .name(name)
        .value(value)
        .domain(domain)
        .path(path)
        .expiresAt(expiresAt)
        .apply { if (persistent) persistent() }
        .build()

    private fun url(spec: String): Uri = Uri.parse(spec)

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
    fun aSessionCookieIsNotWrittenToStorage() {
        val cookie = cookie("session", "A", domain = "example.com", expiresAt = Long.MAX_VALUE, persistent = false)
        val target = url("https://example.com/")

        jar.saveFromResponse(target, listOf(cookie))

        assertNull(storage.getStringSet("cookies_example.com", null))
    }

    @Test
    fun aSessionCookieIsStillSentOnALaterRequest() {
        val cookie = cookie("session", "A", domain = "example.com", expiresAt = Long.MAX_VALUE, persistent = false)
        val target = url("https://example.com/")

        jar.saveFromResponse(target, listOf(cookie))

        assertTrue(jar.loadForRequest(target).any { it.name == "session" && it.value == "A" })
    }

    @Test
    fun aPersistentCookieIsStillWritten() {
        val future = System.currentTimeMillis() + 60_000L
        val cookie = cookie("session", "A", domain = "example.com", expiresAt = future, persistent = true)
        val target = url("https://example.com/")

        jar.saveFromResponse(target, listOf(cookie))

        assertEquals(1, storage.getStringSet("cookies_example.com", null)?.size)
    }

    @Test
    fun clearRemovesEveryStoredCookie() {
        val future = System.currentTimeMillis() + 60_000L
        val persistentCookie = cookie("persistent", "A", domain = "example.com", expiresAt = future, persistent = true)
        val sessionCookie = cookie("session", "B", domain = "other.com", expiresAt = Long.MAX_VALUE, persistent = false)
        jar.saveFromResponse(url("https://example.com/"), listOf(persistentCookie))
        jar.saveFromResponse(url("https://other.com/"), listOf(sessionCookie))

        jar.clear()

        assertTrue(jar.loadForRequest(url("https://example.com/")).isEmpty())
        assertTrue(jar.loadForRequest(url("https://other.com/")).isEmpty())
        assertNull(storage.getStringSet("cookies_example.com", null))
        assertNull(storage.getStringSet("cookies_other.com", null))
    }

    @Test
    fun clearRemovesTheDomainIndex() {
        val future = System.currentTimeMillis() + 60_000L
        val persistentCookie = cookie("persistent", "A", domain = "example.com", expiresAt = future, persistent = true)
        jar.saveFromResponse(url("https://example.com/"), listOf(persistentCookie))

        jar.clear()

        assertNull(storage.getStringSet("_cookie_domains", null))
    }

    @Test
    fun corruptStoredValueDroppedFailClosed() {
        storage.putStringSet(
            "_cookie_domains",
            setOf("bad-base64.example.com", "v1-bad-tag.example.com", "legacy-bad-tag.example.com"),
        )

        // Not valid Base64 at all: rejected by decrypt()'s outer catch around
        // Base64.decode, before gcmDecrypt is ever reached.
        storage.putStringSet("cookies_bad-base64.example.com", setOf("!!!not-valid-ciphertext!!!"))

        // Valid Base64, current framing ([version=1][ivLen][iv][ciphertext]) filled with
        // random bytes. Size 2 + 12 + 32 = 46 clears the "raw.size >= 2 + ivLen +
        // GCM_TAG_LENGTH / 8" guard (2 + 12 + 16 = 30), so decrypt() actually calls
        // gcmDecrypt and this is rejected on AEAD tag verification, not short-circuited
        // by the length check. Cleartext or an attacker's substitute cannot forge a
        // valid tag under our Keystore key, which is exactly the guarantee this test
        // exists to prove.
        val random = java.security.SecureRandom()
        val v1 = ByteArray(2 + 12 + 32).also(random::nextBytes)
        v1[0] = 1
        v1[1] = 12
        storage.putStringSet(
            "cookies_v1-bad-tag.example.com",
            setOf(Base64.encodeToString(v1, Base64.NO_WRAP)),
        )

        // Valid Base64, legacy framing ([ivLen][iv][ciphertext], first byte != version 1)
        // filled with random bytes. Size 1 + 12 + 32 = 45 clears the legacy guard
        // (1 + 12 + 16 = 29), so gcmDecrypt runs on this path too and rejects it on the
        // tag, exercising the legacy-format fail-closed branch separately.
        val legacy = ByteArray(1 + 12 + 32).also(random::nextBytes)
        legacy[0] = 12
        storage.putStringSet(
            "cookies_legacy-bad-tag.example.com",
            setOf(Base64.encodeToString(legacy, Base64.NO_WRAP)),
        )

        assertTrue(jar.loadForRequest(url("https://bad-base64.example.com/")).isEmpty())
        assertTrue(jar.loadForRequest(url("https://v1-bad-tag.example.com/")).isEmpty())
        assertTrue(jar.loadForRequest(url("https://legacy-bad-tag.example.com/")).isEmpty())
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

    @Test
    fun persistedSchemaFieldNamesPinned() {
        val future = System.currentTimeMillis() + 60_000L
        val cookie = cookie("session", "A", domain = "example.com", expiresAt = future)
        val target = url("https://example.com/")

        jar.saveFromResponse(target, listOf(cookie))

        val stored = storage.getStringSet("cookies_example.com", null)!!.single()
        val json = decryptWithJarKey(stored)

        assertEquals(setOf("n", "v", "d", "p", "e", "s", "h", "ho"), json.keys().asSequence().toSet())
    }

    @Test
    fun legacyFramingStillDecodes() {
        val secretKey = SecureCookieJar::class.java.getDeclaredField("secretKey")
            .apply { isAccessible = true }.get(jar) as javax.crypto.SecretKey

        val plaintext = org.json.JSONObject().apply {
            put("n", "session")
            put("v", "A")
            put("d", "example.com")
            put("p", "/")
            put("e", System.currentTimeMillis() + 60_000L)
            put("s", false)
            put("h", false)
            put("ho", true)
        }.toString().toByteArray(Charsets.UTF_8)

        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)

        // Legacy framing predates the version byte: [ivLen][iv][ciphertext].
        val legacy = ByteArray(1 + iv.size + ciphertext.size)
        legacy[0] = iv.size.toByte()
        System.arraycopy(iv, 0, legacy, 1, iv.size)
        System.arraycopy(ciphertext, 0, legacy, 1 + iv.size, ciphertext.size)

        storage.putStringSet("_cookie_domains", setOf("example.com"))
        storage.putStringSet("cookies_example.com", setOf(Base64.encodeToString(legacy, Base64.NO_WRAP)))

        val loaded = jar.loadForRequest(url("https://example.com/"))

        assertTrue(loaded.any { it.name == "session" && it.value == "A" })
    }

    /** Decrypts [encoded] under the jar's current-version framing, for schema-pin assertions. */
    private fun decryptWithJarKey(encoded: String): org.json.JSONObject {
        val secretKey = SecureCookieJar::class.java.getDeclaredField("secretKey")
            .apply { isAccessible = true }.get(jar) as javax.crypto.SecretKey
        val raw = Base64.decode(encoded, Base64.NO_WRAP)
        val ivLen = raw[1].toInt() and 0xFF
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            javax.crypto.Cipher.DECRYPT_MODE,
            secretKey,
            javax.crypto.spec.GCMParameterSpec(128, raw.copyOfRange(2, 2 + ivLen)),
        )
        val plaintext = cipher.doFinal(raw.copyOfRange(2 + ivLen, raw.size))
        return org.json.JSONObject(String(plaintext, Charsets.UTF_8))
    }
}
