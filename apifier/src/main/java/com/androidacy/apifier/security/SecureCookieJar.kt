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
import java.util.concurrent.locks.ReentrantReadWriteLock
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.concurrent.write

/**
 * [CookieJar] backed by a [CookieStorage]. A [Cookie.persistent] cookie is JSON-serialized,
 * AES-GCM encrypted via Android Keystore, Base64-encoded, and written to [storage]; a session
 * cookie (RFC 6265 s5.3 step 3) lives only in the decoded cache for this instance's lifetime.
 */
class SecureCookieJar(
    private val storage: CookieStorage,
    private val publicSuffixList: PublicSuffixList
) : CookieJar {

    private val secretKey: SecretKey? = loadOrCreateKey()

    // Write-through cache of decoded cookies keyed by domain, bounded so a client that talks
    // to many hosts over its lifetime cannot grow one entry per host forever. loadForRequest
    // (once per request) would otherwise re-decrypt every cookie of every domain, a Keystore
    // binder IPC each.
    private val decodedCache = DecodedDomainCache()

    // Guards only the read-merge-write across storage, the shared domain index and the rare
    // prune-on-visit path, all of which need atomicity against a concurrent save. loadForRequest
    // takes no lock: decodedCache synchronizes itself and a plain storage read needs no
    // exclusivity, so a save no longer blocks every concurrent load for hosts it isn't touching.
    private val lock = ReentrantReadWriteLock()

    override fun loadForRequest(uri: Uri): List<Cookie> {
        val host = uri.host?.lowercase() ?: return emptyList()
        val registrable = registrableDomainOf(host)
        val now = System.currentTimeMillis()
        val result = mutableListOf<Cookie>()
        val expiredDomains = mutableListOf<String>()

        for (domain in candidateDomains(registrable)) {
            val cookies = decodedCache.get(domain) ?: loadDomain(domain)
            val valid = cookies.filter { it.expiresAt > now }
            if (valid.isEmpty()) {
                expiredDomains.add(domain)
                continue
            }
            for (cookie in valid) if (cookie.matches(uri)) result.add(cookie)
        }

        if (expiredDomains.isNotEmpty()) {
            lock.write { for (domain in expiredDomains) pruneIfStillExpired(domain, now) }
        }
        return result
    }

    override fun saveFromResponse(uri: Uri, cookies: List<Cookie>) = lock.write {
        if (cookies.isEmpty()) return@write

        val now = System.currentTimeMillis()
        val addedDomains = mutableSetOf<String>()
        val removedDomains = mutableSetOf<String>()

        for (cookie in cookies) {
            val domain = cookie.domain

            val stored = storage.getStringSet(domainKey(domain), null)
                ?.mapNotNull { encoded -> runCatching { decode(encoded) }.getOrNull() }
                ?: emptyList()
            // A session cookie already held for this domain lives only in decodedCache, never
            // in storage, so both have to feed the merge or an overwrite would drop it.
            val existing = (stored + (decodedCache.get(domain) ?: emptyList()))
                .associateBy { it.name to it.path }
                .toMutableMap()

            existing[cookie.name to cookie.path] = cookie

            val validCookies = existing.values.filter { it.expiresAt > now }
            decodedCache.put(domain, validCookies)

            val persistentCookies = validCookies.filter { it.persistent }
            val encoded = persistentCookies.mapNotNull { encode(it) }.toSet()

            // encoded.isNotEmpty() already answers whether this domain still has stored
            // cookies; re-reading storage to ask the same question again would be a round
            // trip for nothing.
            if (encoded.isNotEmpty()) {
                storage.putStringSet(domainKey(domain), encoded)
                addedDomains.add(domain)
                removedDomains.remove(domain)
            } else {
                storage.remove(domainKey(domain))
                removedDomains.add(domain)
                addedDomains.remove(domain)
            }
            if (validCookies.isEmpty()) decodedCache.remove(domain)
        }

        if (addedDomains.isNotEmpty() || removedDomains.isNotEmpty()) {
            val allDomains = getStoredDomains().toMutableSet()
            allDomains.addAll(addedDomains)
            allDomains.removeAll(removedDomains)
            storage.putStringSet(DOMAIN_INDEX_KEY, allDomains)
        }
    }

    override fun clear() = lock.write {
        for (domain in getStoredDomains() + decodedCache.keys()) {
            storage.remove(domainKey(domain))
        }
        storage.remove(DOMAIN_INDEX_KEY)
        decodedCache.clear()
    }

    /** Loads and caches [domain]'s cookies from storage; called outside [lock]. */
    private fun loadDomain(domain: String): List<Cookie> {
        val decoded = storage.getStringSet(domainKey(domain), null)
            ?.mapNotNull { encoded -> runCatching { decode(encoded) }.getOrNull() }
            ?: emptyList()
        decodedCache.put(domain, decoded)
        return decoded
    }

    /**
     * Removes [domain] from storage, the index and the cache, but only if it is still fully
     * expired under [lock]: a concurrent [saveFromResponse] could have refreshed it between
     * [loadForRequest]'s unlocked scan and this call.
     */
    private fun pruneIfStillExpired(domain: String, now: Long) {
        val current = decodedCache.get(domain) ?: loadDomain(domain)
        if (current.any { it.expiresAt > now }) return
        decodedCache.remove(domain)
        storage.remove(domainKey(domain))
        val domains = getStoredDomains()
        if (domain in domains) storage.putStringSet(DOMAIN_INDEX_KEY, domains - domain)
    }

    // decodedCache.keys() covers session cookies, which never enter the storage index.
    private fun candidateDomains(registrable: String): List<String> {
        val fromIndex = getStoredDomains().asSequence().filter { registrableDomainOf(it) == registrable }
        val fromCache = decodedCache.keys().asSequence().filter { registrableDomainOf(it) == registrable }
        return (fromIndex + fromCache).distinct().toList()
    }

    private fun registrableDomainOf(domain: String): String =
        publicSuffixList.effectiveTldPlusOne(domain) ?: domain

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
        // Fail closed: an unavailable cipher drops the cookie. It is never persisted in cleartext.
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
            // Only a persistent cookie is ever written to storage, so anything decoded from
            // here is persistent by construction; the flag itself is not part of the schema.
            .persistent()
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

/**
 * Bounded, access-ordered cache of decoded cookies keyed by domain, evicting the least recently
 * used entry past [maxDomains]. Same shape as `com.androidacy.apifier.client.BreakerRegistry`:
 * a domain evicted here is not lost, only its decode -- the next visit re-reads and re-decrypts it
 * from [SecureCookieJar]'s storage.
 */
private class DecodedDomainCache(private val maxDomains: Int = MAX_CACHED_DOMAINS) {

    private val cache = object : LinkedHashMap<String, List<Cookie>>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, List<Cookie>>): Boolean =
            size > maxDomains
    }

    fun get(domain: String): List<Cookie>? = synchronized(cache) { cache[domain] }

    fun put(domain: String, cookies: List<Cookie>) = synchronized(cache) { cache[domain] = cookies }

    fun remove(domain: String) = synchronized(cache) { cache.remove(domain) }

    fun keys(): Set<String> = synchronized(cache) { LinkedHashSet(cache.keys) }

    fun clear() = synchronized(cache) { cache.clear() }

    private companion object {
        const val MAX_CACHED_DOMAINS = 64
    }
}
