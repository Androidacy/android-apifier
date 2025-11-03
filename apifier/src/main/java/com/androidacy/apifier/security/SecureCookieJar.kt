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
import okhttp3.CookieJar
import okhttp3.HttpUrl

class SecureCookieJar(private val storage: CookieStorage) : CookieJar {

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        val now = System.currentTimeMillis()
        return storage.getStringSet(url.host, null)
            ?.mapNotNull { encoded ->
                runCatching { decode(encoded) }.getOrNull()
            }
            ?.filter { cookie ->
                (cookie.expiresAt > now || cookie.expiresAt == 0L) &&
                        url.encodedPath.startsWith(cookie.path) &&
                        (!cookie.secure || url.isHttps)
            } ?: emptyList()
    }

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        if (cookies.isEmpty()) return

        val now = System.currentTimeMillis()
        val existing = storage.getStringSet(url.host, null)
            ?.mapNotNull { encoded -> runCatching { decode(encoded) }.getOrNull() }
            ?.associateBy { it.name }
            ?.toMutableMap() ?: mutableMapOf()

        cookies.forEach { existing[it.name] = it }

        val valid = existing.values
            .filter { it.expiresAt > now || it.expiresAt == 0L }
            .map { encode(it) }
            .toSet()

        if (valid.isNotEmpty()) {
            storage.putStringSet(url.host, valid)
        } else {
            storage.remove(url.host)
        }
    }

    private fun encode(cookie: Cookie): String {
        val data = listOf(
            cookie.name,
            cookie.value,
            cookie.domain,
            cookie.path,
            cookie.expiresAt.toString(),
            cookie.secure.toString(),
            cookie.httpOnly.toString(),
            cookie.hostOnly.toString(),
            cookie.persistent.toString()
        ).joinToString("|")
        return Base64.encodeToString(data.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    }

    private fun decode(encoded: String): Cookie {
        val data = String(Base64.decode(encoded, Base64.NO_WRAP), Charsets.UTF_8)
        val parts = data.split("|")
        require(parts.size >= 9) { "Invalid cookie format: expected 9 parts, got ${parts.size}" }

        return Cookie.Builder()
            .name(parts[0])
            .value(parts[1])
            .domain(parts[2])
            .path(parts[3])
            .expiresAt(parts[4].toLongOrNull() ?: 0L)
            .apply {
                if (parts[5].toBooleanStrictOrNull() == true) secure()
                if (parts[6].toBooleanStrictOrNull() == true) httpOnly()
                if (parts[7].toBooleanStrictOrNull() == true) hostOnlyDomain(parts[2])
            }
            .build()
    }
}
