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

import java.net.InetAddress

/** Routability category of an IP literal. */
enum class AddressCategory {
    PUBLIC,
    LOOPBACK,
    UNSPECIFIED,
    PRIVATE,
    LINK_LOCAL,
    CGNAT,
    ULA,
    MULTICAST,
    INVALID
}

/** Classifies IP literals and validates host strings without ever resolving a name. */
object AddressClassifier {

    private val SAFE_HOSTNAME = Regex("""^[a-zA-Z0-9_-]{1,63}(\.[a-zA-Z0-9_-]{1,63})*$""")
    private val IPV4_PATTERN = Regex("""\d{1,3}(\.\d{1,3}){3}""")

    /**
     * The category of [ip]. Anything that does not parse as an IP literal is
     * [AddressCategory.INVALID], so an unrecognized answer can never be read as routable.
     */
    fun classify(ip: String): AddressCategory {
        val address = parseLiteral(ip) ?: return AddressCategory.INVALID
        val bytes = address.address
        return when {
            address.isAnyLocalAddress -> AddressCategory.UNSPECIFIED
            address.isLoopbackAddress -> AddressCategory.LOOPBACK
            address.isMulticastAddress -> AddressCategory.MULTICAST
            address.isLinkLocalAddress -> AddressCategory.LINK_LOCAL
            address.isSiteLocalAddress -> AddressCategory.PRIVATE
            isCgnat(bytes) -> AddressCategory.CGNAT
            isUniqueLocal(bytes) -> AddressCategory.ULA
            else -> AddressCategory.PUBLIC
        }
    }

    /** True when [host] is an IP literal, bracketed IPv6 included. */
    fun isIpLiteral(host: String): Boolean {
        val stripped = host.removeSurrounding("[", "]")
        if (stripped.matches(IPV4_PATTERN)) return true
        return ':' in stripped
    }

    /**
     * True when [host] is safe to pass through host-scoped plumbing: only unreserved characters,
     * and every label 1 to 63 bytes. The label rule matches what [DnsWireCodec.buildQuery]
     * accepts, so a hostname that passes here can always be turned into a query. A trailing dot
     * leaves an empty label and both reject it.
     */
    fun isSafeHostname(host: String): Boolean = SAFE_HOSTNAME.matches(host)

    /**
     * [InetAddress.getByName] resolves anything it does not recognize as a literal, so the input
     * is shape-checked first: no classification may trigger a DNS lookup.
     */
    private fun parseLiteral(ip: String): InetAddress? {
        val stripped = ip.removeSurrounding("[", "]")
        val isIpv4 = stripped.matches(IPV4_PATTERN) &&
            stripped.split('.').all { (it.toIntOrNull() ?: 256) <= 255 }
        if (!isIpv4 && ':' !in stripped) return null
        return try {
            InetAddress.getByName(stripped)
        } catch (e: java.net.UnknownHostException) {
            null
        }
    }

    /** RFC 6598 shared address space, which [InetAddress] has no predicate for. */
    private fun isCgnat(bytes: ByteArray): Boolean =
        bytes.size == 4 && (bytes[0].toInt() and 0xFF) == 100 && (bytes[1].toInt() and 0xFF) in 64..127

    /** RFC 4193 unique local addresses, which [InetAddress] has no predicate for. */
    private fun isUniqueLocal(bytes: ByteArray): Boolean =
        bytes.size == 16 && (bytes[0].toInt() and 0xFE) == 0xFC
}
