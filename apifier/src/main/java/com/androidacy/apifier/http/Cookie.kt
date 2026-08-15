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
import java.net.IDN
import java.util.Calendar
import java.util.TimeZone

/**
 * An HTTP cookie, per RFC 6265. Instances are immutable; build one with [Builder] or parse one
 * from a `Set-Cookie` header with [parse].
 */
class Cookie private constructor(
    val name: String,
    val value: String,
    val domain: String,
    val path: String,
    val expiresAt: Long,
    val secure: Boolean,
    val httpOnly: Boolean,
    val hostOnly: Boolean,
    /** RFC 6265 s5.3 step 3: true only when the `Set-Cookie` carried `Expires` or `Max-Age`. */
    val persistent: Boolean,
) {

    /**
     * True when this cookie should be sent on a request to [uri]: domain-match ([hostOnly]
     * requires exact host equality, otherwise a dot-bounded suffix match), path-match with a
     * `/` boundary, and, for [secure] cookies, an `https` scheme.
     */
    fun matches(uri: Uri): Boolean {
        if (secure && !uri.scheme.equals("https", ignoreCase = true)) return false
        val host = uri.host?.lowercase() ?: return false
        val hostMatches = if (hostOnly) host == domain else domainMatches(host, domain)
        if (!hostMatches) return false
        return pathMatches(uri.path?.takeIf { it.startsWith("/") } ?: "/", path)
    }

    class Builder {
        private var name: String? = null
        private var value: String? = null
        private var domain: String? = null
        private var path: String = "/"
        private var expiresAt: Long = Long.MAX_VALUE
        private var secure: Boolean = false
        private var httpOnly: Boolean = false
        private var hostOnly: Boolean = false
        private var persistent: Boolean = false

        fun name(name: String): Builder = apply { this.name = name }

        fun value(value: String): Builder = apply { this.value = value }

        /** Marks this a domain cookie: sent to [domain] and every subdomain. */
        fun domain(domain: String): Builder = apply {
            this.domain = domain
            this.hostOnly = false
        }

        /** Marks this a host-only cookie: sent only to the exact host [domain]. */
        fun hostOnlyDomain(domain: String): Builder = apply {
            this.domain = domain
            this.hostOnly = true
        }

        fun path(path: String): Builder = apply { this.path = path }

        fun expiresAt(expiresAt: Long): Builder = apply { this.expiresAt = expiresAt }

        fun secure(): Builder = apply { this.secure = true }

        fun httpOnly(): Builder = apply { this.httpOnly = true }

        /** Marks this cookie for storage beyond the jar's lifetime, per [Cookie.persistent]. */
        fun persistent(): Builder = apply { this.persistent = true }

        fun build(): Cookie = Cookie(
            name = checkNotNull(name) { "name == null" },
            value = checkNotNull(value) { "value == null" },
            domain = checkNotNull(domain) { "domain == null" },
            path = path,
            expiresAt = expiresAt,
            secure = secure,
            httpOnly = httpOnly,
            hostOnly = hostOnly,
            persistent = persistent,
        )
    }

    companion object {
        private val MONTHS = listOf(
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        )
        private val RFC1123 = Regex(
            """^[A-Za-z]{3}, (\d{2}) ([A-Za-z]{3}) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$""",
        )
        private val RFC850 = Regex(
            """^[A-Za-z]+, (\d{2})-([A-Za-z]{3})-(\d{2}) (\d{2}):(\d{2}):(\d{2}) GMT$""",
        )
        private val ASCTIME = Regex(
            """^[A-Za-z]{3} ([A-Za-z]{3}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4})$""",
        )

        // Generous headroom against a huge Max-Age overflowing the epoch-millis sum below;
        // still centuries longer than any real session needs.
        private const val MAX_AGE_CAP_SECONDS = 100_000_000_000L

        /**
         * Parses one `Set-Cookie` header value against the request it answered. Returns null
         * when the cookie is malformed or fails RFC 6265 s5.3 domain validation -- including
         * a Domain attribute that names a public suffix the request host isn't itself, which
         * is the control that stops a public-suffix host from setting cookies for every site
         * beneath it.
         */
        fun parse(uri: Uri, setCookie: String, psl: PublicSuffixList): Cookie? {
            val parts = setCookie.split(";")
            val firstEquals = parts[0].indexOf('=')
            if (firstEquals == -1) return null
            val name = parts[0].substring(0, firstEquals).trim()
            val value = parts[0].substring(firstEquals + 1).trim()
            if (name.isEmpty()) return null

            var expiresAt = Long.MAX_VALUE
            var maxAgeSet = false
            var persistent = false
            var domainAttr: String? = null
            var pathAttr: String? = null
            var secure = false
            var httpOnly = false
            val now = System.currentTimeMillis()

            for (i in 1 until parts.size) {
                val attr = parts[i]
                val eq = attr.indexOf('=')
                val attrName = (if (eq == -1) attr else attr.substring(0, eq)).trim()
                val attrValue = if (eq == -1) "" else attr.substring(eq + 1).trim()
                when {
                    attrName.equals("max-age", ignoreCase = true) -> {
                        val seconds = attrValue.toLongOrNull() ?: continue
                        maxAgeSet = true
                        persistent = true
                        expiresAt = if (seconds <= 0) 0L else now + seconds.coerceAtMost(MAX_AGE_CAP_SECONDS) * 1000
                    }
                    attrName.equals("expires", ignoreCase = true) && !maxAgeSet ->
                        parseExpires(attrValue)?.let { expiresAt = it; persistent = true }
                    attrName.equals("domain", ignoreCase = true) -> domainAttr = attrValue
                    attrName.equals("path", ignoreCase = true) -> pathAttr = attrValue
                    attrName.equals("secure", ignoreCase = true) -> secure = true
                    attrName.equals("httponly", ignoreCase = true) -> httpOnly = true
                }
            }

            val requestHost = uri.host?.lowercase() ?: return null
            val hostOnly: Boolean
            val cookieDomain: String
            if (domainAttr == null || domainAttr.isEmpty()) {
                hostOnly = true
                cookieDomain = requestHost
            } else {
                var d = domainAttr.trim()
                if (d.startsWith(".")) d = d.substring(1)
                d = try { IDN.toASCII(d.lowercase()) } catch (e: IllegalArgumentException) { return null }
                if (d.isEmpty()) return null
                // RFC 6265 s5.3 step 5: an IP-literal request host accepts only an identical
                // Domain attribute, never a dotted-suffix match against its own octets.
                hostOnly = if (isIpLiteral(requestHost)) {
                    if (d != requestHost) return null
                    true
                } else if (!domainMatches(requestHost, d)) {
                    return null
                } else if (psl.isPublicSuffix(d)) {
                    if (d != requestHost) return null
                    true
                } else {
                    false
                }
                cookieDomain = d
            }

            val cookiePath = pathAttr?.takeIf { it.startsWith("/") } ?: defaultPath(uri.path)

            val builder = Builder().name(name).value(value).path(cookiePath).expiresAt(expiresAt)
            if (hostOnly) builder.hostOnlyDomain(cookieDomain) else builder.domain(cookieDomain)
            if (secure) builder.secure()
            if (httpOnly) builder.httpOnly()
            if (persistent) builder.persistent()
            return builder.build()
        }

        /** Parses every `Set-Cookie` value in [headers], dropping the ones [parse] rejects. */
        fun parseAll(uri: Uri, headers: Headers, psl: PublicSuffixList): List<Cookie> =
            headers.values("Set-Cookie").mapNotNull { parse(uri, it, psl) }

        /** RFC 6265 s5.1.4: the request path up to, not including, its final `/`-terminated segment. */
        private fun defaultPath(uriPath: String?): String {
            val path = uriPath ?: ""
            if (!path.startsWith("/")) return "/"
            val lastSlash = path.lastIndexOf('/')
            return if (lastSlash <= 0) "/" else path.substring(0, lastSlash)
        }

        /** True for a dotted-quad IPv4 literal or any host containing a `:` (bracketed IPv6). */
        private fun isIpLiteral(host: String): Boolean {
            if (host.contains(":")) return true
            val labels = host.split(".")
            return labels.all { it.isNotEmpty() && it.all(Char::isDigit) }
        }

        /** RFC 6265 s5.1.3: exact match, or [domain] is a suffix of [host] on a label boundary. */
        private fun domainMatches(host: String, domain: String): Boolean {
            if (host == domain) return true
            if (!host.endsWith(domain)) return false
            val prefixLength = host.length - domain.length
            return prefixLength > 0 && host[prefixLength - 1] == '.'
        }

        /** RFC 6265 s5.1.4: exact match, or [cookiePath] is a prefix of [requestPath] on a `/` boundary. */
        private fun pathMatches(requestPath: String, cookiePath: String): Boolean {
            if (requestPath == cookiePath) return true
            if (!requestPath.startsWith(cookiePath)) return false
            return cookiePath.endsWith("/") || requestPath[cookiePath.length] == '/'
        }

        /**
         * Parses an `Expires` value in RFC 1123, RFC 850, or asctime form. RFC 850's two-digit
         * year is normalized per RFC 6265 s5.1.1: 69 and below is 20xx, 70 and above is 19xx.
         * Hand-rolled: [java.text.SimpleDateFormat]'s pivot year for a bare `yy` pattern
         * doesn't match that rule.
         */
        private fun parseExpires(raw: String): Long? {
            val value = raw.trim().replace(Regex("\\s+"), " ")

            RFC1123.find(value)?.groupValues?.let { g ->
                return buildMillis(g[3].toInt(), g[2], g[1].toInt(), g[4].toInt(), g[5].toInt(), g[6].toInt())
            }
            RFC850.find(value)?.groupValues?.let { g ->
                val year = g[3].toInt().let { if (it <= 69) 2000 + it else 1900 + it }
                return buildMillis(year, g[2], g[1].toInt(), g[4].toInt(), g[5].toInt(), g[6].toInt())
            }
            ASCTIME.find(value)?.groupValues?.let { g ->
                return buildMillis(g[6].toInt(), g[1], g[2].toInt(), g[3].toInt(), g[4].toInt(), g[5].toInt())
            }
            return null
        }

        private fun buildMillis(year: Int, monthName: String, day: Int, hour: Int, minute: Int, second: Int): Long? {
            val month = MONTHS.indexOfFirst { it.equals(monthName, ignoreCase = true) }
            if (month == -1) return null
            val calendar = Calendar.getInstance(TimeZone.getTimeZone("GMT"))
            calendar.clear()
            calendar.set(year, month, day, hour, minute, second)
            return calendar.timeInMillis
        }
    }
}

/** Persists and supplies cookies across requests. */
interface CookieJar {
    /** Cookies to send with a request to [uri], already filtered to what applies there. */
    fun loadForRequest(uri: Uri): List<Cookie>

    /** Persists [cookies] received in the response to a request against [uri]. */
    fun saveFromResponse(uri: Uri, cookies: List<Cookie>)

    /** Drops every cookie this jar holds, in memory and in whatever it persists to. */
    fun clear() {}
}
