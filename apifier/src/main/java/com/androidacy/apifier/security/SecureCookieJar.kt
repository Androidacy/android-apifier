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

import android.annotation.SuppressLint
import android.net.Uri
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import com.androidacy.apifier.http.Cookie
import com.androidacy.apifier.http.CookieJar
import org.json.JSONObject
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantReadWriteLock
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.concurrent.read
import kotlin.concurrent.write

/** [CookieJar] backed by a [CookieStorage]. Cookies are JSON-serialized, AES-GCM encrypted via Android Keystore, and Base64-encoded. */
class SecureCookieJar(private val storage: CookieStorage) : CookieJar {

    private val secretKey: SecretKey? = loadOrCreateKey()

    // Write-through cache of decoded cookies keyed by domain. The hot request path
    // (loadForRequest, once per request) would otherwise re-decrypt every cookie of
    // every domain, a Keystore binder IPC each. Reads take the shared read lock so
    // concurrent requests no longer serialize; writes (saveFromResponse) take the
    // write lock and refresh the affected domain, so the consumer's CookieStorage is
    // never touched by a read and a write at the same time.
    private val decodedCache = ConcurrentHashMap<String, List<Cookie>>()
    private val lock = ReentrantReadWriteLock()

    override fun loadForRequest(uri: Uri): List<Cookie> = lock.read {
        val now = System.currentTimeMillis()
        val result = mutableListOf<Cookie>()

        // Check all stored domains for cookies that match this URL
        for (domain in getStoredDomains()) {
            val cookies = decodedCache.computeIfAbsent(domain) { d ->
                storage.getStringSet(domainKey(d), null)
                    ?.mapNotNull { encoded -> runCatching { decode(encoded) }.getOrNull() }
                    ?: emptyList()
            }

            for (cookie in cookies) {
                if (cookie.expiresAt <= now) continue
                if (!cookie.matches(uri)) continue
                result.add(cookie)
            }
        }
        result
    }

    override fun saveFromResponse(uri: Uri, cookies: List<Cookie>) = lock.write {
        if (cookies.isEmpty()) return@write

        val now = System.currentTimeMillis()
        val domainsChanged = mutableSetOf<String>()

        for (cookie in cookies) {
            val domain = cookie.domain
            domainsChanged.add(domain)

            val existing = storage.getStringSet(domainKey(domain), null)
                ?.mapNotNull { encoded -> runCatching { decode(encoded) }.getOrNull() }
                ?.associateBy { it.name to it.path }
                ?.toMutableMap() ?: mutableMapOf()

            existing[cookie.name to cookie.path] = cookie

            val validCookies = existing.values.filter { it.expiresAt > now }
            val encoded = validCookies.mapNotNull { encode(it) }.toSet()

            if (encoded.isNotEmpty()) {
                storage.putStringSet(domainKey(domain), encoded)
                decodedCache[domain] = validCookies
            } else {
                storage.remove(domainKey(domain))
                decodedCache.remove(domain)
            }
        }

        // Update domain index: prune domains whose storage was cleared
        val allDomains = getStoredDomains().toMutableSet()
        for (domain in domainsChanged) {
            if (storage.getStringSet(domainKey(domain), null).isNullOrEmpty()) {
                allDomains.remove(domain)
            } else {
                allDomains.add(domain)
            }
        }
        storage.putStringSet(DOMAIN_INDEX_KEY, allDomains)
    }

    private fun getStoredDomains(): Set<String> =
        storage.getStringSet(DOMAIN_INDEX_KEY, null) ?: emptySet()

    private fun domainKey(domain: String): String = "cookies_$domain"

    private fun encode(cookie: Cookie): String? {
        val json = JSONObject().apply {
            put("n", cookie.name)
            put("v", cookie.value)
            put("d", cookie.domain)
            put("p", cookie.path)
            put("e", cookie.expiresAt)
            put("s", cookie.secure)
            put("h", cookie.httpOnly)
            put("ho", cookie.hostOnly)
        }
        val plaintext = json.toString().toByteArray(Charsets.UTF_8)
        // Fail closed: if encryption is unavailable, drop the cookie rather than
        // persisting it in cleartext.
        return encrypt(plaintext)
    }

    private fun decode(encoded: String): Cookie? {
        // Fail closed: only authenticated ciphertext is trusted. Anything that does
        // not decrypt (legacy cleartext, tampered or truncated blobs) is dropped.
        val jsonBytes = decrypt(encoded) ?: return null
        val json = JSONObject(String(jsonBytes, Charsets.UTF_8))
        return Cookie.Builder()
            .name(json.getString("n"))
            .value(json.getString("v"))
            .domain(json.getString("d"))
            .path(json.getString("p"))
            .expiresAt(json.getLong("e"))
            .apply {
                if (json.optBoolean("s")) secure()
                if (json.optBoolean("h")) httpOnly()
                if (json.optBoolean("ho")) hostOnlyDomain(json.getString("d"))
            }
            .build()
    }

    private fun encrypt(plaintext: ByteArray): String? {
        val key = secretKey ?: return null
        return try {
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORM)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(plaintext)
            // Frame as version (1 byte) + IV length (1 byte) + IV + ciphertext, then
            // Base64. The version tag lets decode reject anything not written as
            // authenticated ciphertext instead of trusting it as plaintext.
            val output = ByteArray(2 + iv.size + ciphertext.size)
            output[0] = FORMAT_VERSION.toByte()
            output[1] = iv.size.toByte()
            System.arraycopy(iv, 0, output, 2, iv.size)
            System.arraycopy(ciphertext, 0, output, 2 + iv.size, ciphertext.size)
            Base64.encodeToString(output, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.w(TAG, "Cookie encryption failed: ${e.message}")
            null
        }
    }

    private fun decrypt(encoded: String): ByteArray? {
        val key = secretKey ?: return null
        return try {
            val raw = Base64.decode(encoded, Base64.NO_WRAP)
            if (raw.size < 2) return null
            if ((raw[0].toInt() and 0xFF) == FORMAT_VERSION) {
                // Current framing: [version][ivLen][iv][ciphertext].
                val ivLen = raw[1].toInt() and 0xFF
                if (raw.size < 2 + ivLen + GCM_TAG_LENGTH / 8) return null
                gcmDecrypt(key, raw.copyOfRange(2, 2 + ivLen), raw.copyOfRange(2 + ivLen, raw.size))
            } else {
                // Legacy framing [ivLen][iv][ciphertext], written before the version
                // tag existed. Accepted only because it authenticates under our
                // Keystore key: cleartext or attacker-substituted blobs cannot forge a
                // valid GCM tag, so fail-closed still holds. The offsets are treated as
                // untrusted since a mismatched first byte may just be corrupt input.
                val ivLen = raw[0].toInt() and 0xFF
                if (raw.size < 1 + ivLen + GCM_TAG_LENGTH / 8) return null
                gcmDecrypt(key, raw.copyOfRange(1, 1 + ivLen), raw.copyOfRange(1 + ivLen, raw.size))
            }
        } catch (_: Exception) {
            // Bad Base64, failed GCM authentication, or unusable key: reject.
            null
        }
    }

    private fun gcmDecrypt(key: SecretKey, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH, iv))
        return cipher.doFinal(ciphertext)
    }

    /**
     * Load an existing key, or generate one with the best available hardware backing:
     * StrongBox (secure element) → TEE/TrustZone → software Keystore. Null when none is
     * available, which drops cookies instead of persisting them in cleartext.
     */
    private fun loadOrCreateKey(): SecretKey? {
        return try {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            val entry = ks.getEntry(KEY_ALIAS, null)
            if (entry is KeyStore.SecretKeyEntry) {
                return entry.secretKey
            }
            generateStrongBoxKey() ?: generateDefaultKey()
        } catch (e: Exception) {
            Log.w(TAG, "Android Keystore unavailable, cookies will not be persisted: ${e.message}")
            null
        }
    }

    /** Attempt key generation in StrongBox secure element. Requires API 28+. */
    @SuppressLint("NewApi")
    private fun generateStrongBoxKey(): SecretKey? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        return try {
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setIsStrongBoxBacked(true)
                .build()
            val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            keyGen.init(spec)
            keyGen.generateKey().also {
                Log.d(TAG, "Cookie encryption key stored in StrongBox")
            }
        } catch (e: Exception) {
            // StrongBoxUnavailableException or unsupported algorithm: fall through
            Log.d(TAG, "StrongBox unavailable, falling back to TEE/software: ${e.message}")
            null
        }
    }

    /** Generate key in default Keystore (TEE-backed if available, software otherwise). */
    private fun generateDefaultKey(): SecretKey? {
        return try {
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            keyGen.init(spec)
            keyGen.generateKey().also {
                Log.d(TAG, "Cookie encryption key stored in Keystore (TEE/software)")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Keystore key generation failed, cookies will not be encrypted: ${e.message}")
            null
        }
    }

    companion object {
        private const val TAG = "SecureCookieJar"
        private const val DOMAIN_INDEX_KEY = "_cookie_domains"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS = "apifier_cookie_key"
        private const val AES_GCM_TRANSFORM = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH = 128
        private const val FORMAT_VERSION = 1
    }
}
