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
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** [CookieJar] backed by a [CookieStorage]. Cookies are JSON-serialized, AES-GCM encrypted via Android Keystore, and Base64-encoded. */
class SecureCookieJar(private val storage: CookieStorage) : CookieJar {

    private val secretKey: SecretKey? = loadOrCreateKey()

    @Synchronized
    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        val now = System.currentTimeMillis()
        val result = mutableListOf<Cookie>()

        // Check all stored domains for cookies that match this URL
        for (domain in getStoredDomains()) {
            val cookies = storage.getStringSet(domainKey(domain), null)
                ?.mapNotNull { encoded -> runCatching { decode(encoded) }.getOrNull() }
                ?: continue

            for (cookie in cookies) {
                if (cookie.expiresAt <= now) continue
                if (!cookie.matches(url)) continue
                result.add(cookie)
            }
        }
        return result
    }

    @Synchronized
    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        if (cookies.isEmpty()) return

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

            val valid = existing.values
                .filter { it.expiresAt > now }
                .map { encode(it) }
                .toSet()

            if (valid.isNotEmpty()) {
                storage.putStringSet(domainKey(domain), valid)
            } else {
                storage.remove(domainKey(domain))
            }
        }

        // Update domain index — prune domains whose storage was cleared
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

    private fun encode(cookie: Cookie): String {
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
        return encrypt(plaintext) ?: Base64.encodeToString(plaintext, Base64.NO_WRAP)
    }

    private fun decode(encoded: String): Cookie {
        val jsonBytes = decrypt(encoded) ?: Base64.decode(encoded, Base64.NO_WRAP)
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
            // Prefix IV length (1 byte) + IV + ciphertext, then Base64
            val output = ByteArray(1 + iv.size + ciphertext.size)
            output[0] = iv.size.toByte()
            System.arraycopy(iv, 0, output, 1, iv.size)
            System.arraycopy(ciphertext, 0, output, 1 + iv.size, ciphertext.size)
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
            val ivLen = raw[0].toInt() and 0xFF
            if (raw.size < 1 + ivLen + GCM_TAG_LENGTH / 8) return null
            val iv = raw.copyOfRange(1, 1 + ivLen)
            val ciphertext = raw.copyOfRange(1 + ivLen, raw.size)
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORM)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH, iv))
            cipher.doFinal(ciphertext)
        } catch (_: Exception) {
            // Decryption failed — may be legacy unencrypted data
            null
        }
    }

    /**
     * Load an existing key, or generate one with the best available hardware backing:
     * StrongBox (secure element) → TEE/TrustZone → software Keystore → null (Base64 fallback).
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
            Log.w(TAG, "Android Keystore unavailable, cookies will not be encrypted: ${e.message}")
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
            // StrongBoxUnavailableException or unsupported algorithm — fall through
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
    }
}
