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

import com.androidacy.apifier.client.NetworkConfigBuilder
import java.net.InetAddress

/** Builder passed to [hostIpPins]; see that function for what declaring a pin does. */
class HostIpPinsBuilder {
    private val pins = mutableMapOf<String, MutableSet<String>>()

    /** Declares the IPv4 and/or IPv6 literals [domain] is allowed to resolve to. */
    fun pin(domain: String, vararg addresses: String) {
        require(AddressClassifier.isSafeHostname(domain)) { "Unsafe pinned domain: \"$domain\"" }
        require(addresses.isNotEmpty()) { "pin(\"$domain\") needs at least one address" }
        addresses.forEach { address ->
            require(AddressClassifier.isIpLiteral(address)) { "Not an IP literal: \"$address\"" }
        }
        pins.getOrPut(domain.lowercase()) { mutableSetOf() }.addAll(addresses)
    }

    fun build(): Map<String, Set<String>> = pins.mapValues { it.value.toSet() }
}

/**
 * Declares the addresses each host is expected to resolve to. Configuring any pin makes
 * [com.androidacy.apifier.client.NetworkConfig.ensureTrustworthyResolver] a no-op: enforcement is
 * on regardless of that flag.
 *
 * Unusable for a host behind geo-DNS fronting, where legitimate answers differ by resolver vantage
 * point: a pin there rejects traffic as often as an attacker would. A pin outliving an address
 * migration refuses every call to that host until the pin is updated.
 */
fun NetworkConfigBuilder.hostIpPins(block: HostIpPinsBuilder.() -> Unit) {
    hostIpPins = HostIpPinsBuilder().apply(block).build()
}

/** Compares a host's declared pins against a resolved answer, on byte form. */
internal object HostIpPins {

    /** True when [host] has pins declared and none of [resolvedAddresses] is among them. */
    fun refuses(pins: Map<String, Set<String>>, host: String, resolvedAddresses: List<String>): Boolean {
        val declared = pins[host.lowercase()]?.mapNotNull(::canonical)?.toSet() ?: return false
        return resolvedAddresses.mapNotNull(::canonical).none { it in declared }
    }

    /** Byte form, so `2606:4700::1111` and its expanded spelling compare equal. */
    private fun canonical(ip: String): String? {
        if (!AddressClassifier.isIpLiteral(ip)) return null
        return runCatching {
            InetAddress.getByName(ip.removeSurrounding("[", "]")).address.joinToString("") { "%02x".format(it) }
        }.getOrNull()
    }
}
