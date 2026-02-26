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
package com.androidacy.apifier.client

import android.util.Log
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.IDN
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.net.URLEncoder
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory

internal class DohResolver(private val config: DohConfig) {

    internal data class DnsRecord(
        val hostname: String,
        val addresses: List<String>,
        val ttlSeconds: Long,
        val resolvedAtMillis: Long
    ) {
        fun isExpired(maxTtl: Long, minTtl: Long): Boolean {
            val effectiveTtl = ttlSeconds.coerceIn(minTtl, maxTtl)
            return System.currentTimeMillis() - resolvedAtMillis > effectiveTtl * 1000
        }

        fun isStale(staleCacheMaxAge: Long): Boolean {
            return System.currentTimeMillis() - resolvedAtMillis > staleCacheMaxAge * 1000
        }
    }

    private class ProviderHealth {
        private val consecutiveFailures = AtomicInteger(0)
        private val backoffUntilMillis = AtomicLong(0)

        fun recordFailure() {
            val failures = consecutiveFailures.updateAndGet { it.coerceAtMost(9) + 1 }
            val backoffMs = (1000L * (1 shl failures.coerceAtMost(5)))
                .coerceAtMost(30_000L)
            backoffUntilMillis.set(System.currentTimeMillis() + backoffMs)
        }

        fun recordSuccess() {
            consecutiveFailures.set(0)
            backoffUntilMillis.set(0)
        }

        fun isAvailable(): Boolean = System.currentTimeMillis() >= backoffUntilMillis.get()
    }

    private val cache = ConcurrentHashMap<String, DnsRecord>()
    private val providerHealth = ConcurrentHashMap<DohProvider, ProviderHealth>()
    private val rulesDirty = AtomicBoolean(false)
    private val dohSslSocketFactory: SSLSocketFactory = createSystemOnlySslSocketFactory()
    @Volatile private var ipv6Available: Boolean = probeIpv6()

    fun resolve(hostname: String): List<String>? {
        if (isIpAddress(hostname)) return null

        // Check cache for non-expired entry
        cache[hostname]?.let { record ->
            if (!record.isExpired(config.maxTtlSeconds, config.minTtlSeconds)) {
                return record.addresses
            }
        }

        // Try providers
        for (provider in config.providers) {
            val health = providerHealth.getOrPut(provider) { ProviderHealth() }
            if (!health.isAvailable()) continue

            val record = try {
                queryProvider(provider, hostname)
            } catch (e: Exception) {
                Log.d(TAG, "Provider ${provider.name} failed for $hostname: ${e.message}")
                health.recordFailure()
                null
            }

            if (record != null && record.addresses.isNotEmpty()) {
                health.recordSuccess()
                cacheRecord(record)
                return record.addresses
            }
        }

        // Stale cache fallback
        if (config.useStaleCache) {
            cache[hostname]?.let { record ->
                if (!record.isStale(config.staleCacheMaxAgeSeconds)) {
                    Log.d(TAG, "Using stale cache for $hostname")
                    return record.addresses
                }
            }
        }

        return null
    }

    fun buildHostResolverRules(): String? {
        if (cache.isEmpty()) return null
        val rules = cache.values
            .filter { record -> SAFE_HOSTNAME.matches(record.hostname) }
            .joinToString(", ") { record ->
                // HostResolverRules only accept a single address, bypassing Cronet's
                // own Happy Eyeballs. Pick based on probed IPv6 reachability.
                val ip = if (ipv6Available) {
                    record.addresses.first()
                } else {
                    record.addresses.firstOrNull { !it.contains(':') }
                        ?: record.addresses.first()
                }
                "MAP ${record.hostname} $ip"
            }
        return rules.ifEmpty { null }
    }

    fun consumeRulesDirty(): Boolean = rulesDirty.getAndSet(false)

    fun preResolve(domains: List<String>) {
        for (domain in domains) {
            resolve(domain)
        }
    }

    internal fun isIpAddress(host: String): Boolean {
        val stripped = host.removeSurrounding("[", "]")
        if (stripped.matches(IPV4_PATTERN)) return true
        if (':' in stripped) return true
        return false
    }

    private fun isPublicAddress(ip: String): Boolean {
        return try {
            val addr = InetAddress.getByName(ip)
            !addr.isLoopbackAddress && !addr.isLinkLocalAddress &&
                !addr.isSiteLocalAddress && !addr.isAnyLocalAddress &&
                !addr.isMulticastAddress
        } catch (_: Exception) {
            false
        }
    }

    private fun isValidIPv4(ip: String): Boolean {
        return try {
            val addr = InetAddress.getByName(ip)
            addr is Inet4Address && isPublicAddress(ip)
        } catch (_: Exception) {
            false
        }
    }

    private fun isValidIPv6(ip: String): Boolean {
        return try {
            val addr = InetAddress.getByName(ip)
            addr !is Inet4Address && isPublicAddress(ip)
        } catch (_: Exception) {
            false
        }
    }

    private fun readBounded(stream: java.io.InputStream, maxSize: Int): ByteArray {
        val baos = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        var total = 0
        while (true) {
            val n = stream.read(buf)
            if (n == -1) break
            total += n
            if (total > maxSize) throw Exception("DNS response exceeds $maxSize bytes")
            baos.write(buf, 0, n)
        }
        return baos.toByteArray()
    }

    private fun createSystemOnlySslSocketFactory(): SSLSocketFactory {
        return try {
            val fullStore = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            val systemStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
            for (alias in fullStore.aliases()) {
                if (alias.startsWith("system:")) {
                    systemStore.setCertificateEntry(alias, fullStore.getCertificate(alias))
                }
            }
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(systemStore)
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, tmf.trustManagers, null)
            ctx.socketFactory
        } catch (e: Exception) {
            Log.w(TAG, "Failed to create system-only TrustManager, using default: ${e.message}")
            SSLContext.getDefault().socketFactory
        }
    }

    private fun applyDohTls(conn: HttpsURLConnection) {
        conn.sslSocketFactory = dohSslSocketFactory
    }

    @Synchronized
    private fun cacheRecord(record: DnsRecord) {
        // Evict oldest entries if at capacity
        if (cache.size >= config.maxCacheEntries && !cache.containsKey(record.hostname)) {
            val oldest = cache.entries.minByOrNull { it.value.resolvedAtMillis }
            oldest?.let { cache.remove(it.key) }
        }
        cache[record.hostname] = record
        rulesDirty.set(true)
    }

    private fun queryProvider(provider: DohProvider, hostname: String): DnsRecord? {
        // Dual-stack resolution: query both A and AAAA, combine with IPv6 first
        // (Happy Eyeballs ordering per RFC 8305)
        val v6Record = try {
            querySingleType(provider, hostname, DNS_TYPE_AAAA)
        } catch (e: Exception) {
            Log.d(TAG, "AAAA query failed for ${provider.name}/$hostname: ${e.message}")
            null
        }

        val v4Record = try {
            querySingleType(provider, hostname, DNS_TYPE_A)
        } catch (e: Exception) {
            Log.d(TAG, "A query failed for ${provider.name}/$hostname: ${e.message}")
            null
        }

        val allAddresses = mutableListOf<String>()
        var minTtl = Long.MAX_VALUE

        v6Record?.let {
            allAddresses.addAll(it.addresses)
            minTtl = minOf(minTtl, it.ttlSeconds)
        }
        v4Record?.let {
            allAddresses.addAll(it.addresses)
            minTtl = minOf(minTtl, it.ttlSeconds)
        }

        if (allAddresses.isEmpty()) return null

        return DnsRecord(
            hostname = hostname,
            addresses = allAddresses,
            ttlSeconds = if (minTtl == Long.MAX_VALUE) config.minTtlSeconds else minTtl,
            resolvedAtMillis = System.currentTimeMillis()
        )
    }

    private fun querySingleType(provider: DohProvider, hostname: String, queryType: Int): DnsRecord? {
        // Primary: RFC 8484 binary POST
        return try {
            queryBinary(provider, hostname, queryType)
        } catch (e: Exception) {
            Log.d(TAG, "Binary query (type=$queryType) failed for ${provider.name}, trying JSON: ${e.message}")
            // Fallback: JSON GET
            queryJson(provider, hostname, queryType)
        }
    }

    private fun queryBinary(provider: DohProvider, hostname: String, queryType: Int): DnsRecord {
        val wireQuery = buildDnsWireQuery(hostname, queryType)
        val url = URL(provider.endpoint)
        val conn = url.openConnection() as HttpsURLConnection
        try {
            applyDohTls(conn)
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/dns-message")
            conn.setRequestProperty("Accept", "application/dns-message")
            conn.connectTimeout = config.queryTimeoutMs
            conn.readTimeout = config.queryTimeoutMs
            conn.doOutput = true

            conn.outputStream.use { it.write(wireQuery) }

            if (conn.responseCode != 200) {
                throw Exception("DoH binary query returned HTTP ${conn.responseCode}")
            }

            val responseBytes = conn.inputStream.use { readBounded(it, MAX_DNS_RESPONSE_SIZE) }
            return parseDnsWireResponse(hostname, responseBytes, queryType)
        } finally {
            conn.disconnect()
        }
    }

    private fun queryJson(provider: DohProvider, hostname: String, queryType: Int): DnsRecord {
        val encodedHostname = URLEncoder.encode(hostname, "UTF-8")
        val typeParam = if (queryType == DNS_TYPE_AAAA) "AAAA" else "A"
        val url = URL("${provider.endpoint}?name=$encodedHostname&type=$typeParam")
        val conn = url.openConnection() as HttpsURLConnection
        try {
            applyDohTls(conn)
            conn.requestMethod = "GET"
            conn.setRequestProperty("Accept", "application/dns-json")
            conn.connectTimeout = config.queryTimeoutMs
            conn.readTimeout = config.queryTimeoutMs

            if (conn.responseCode != 200) {
                throw Exception("DoH JSON query returned HTTP ${conn.responseCode}")
            }

            val bodyBytes = conn.inputStream.use { readBounded(it, MAX_DNS_RESPONSE_SIZE) }
            val json = JSONObject(String(bodyBytes, Charsets.UTF_8))

            if (json.optInt("Status", -1) != 0) {
                throw Exception("DoH JSON returned non-zero status: ${json.optInt("Status")}")
            }

            val answers = json.optJSONArray("Answer") ?: throw Exception("No Answer section")
            val addresses = mutableListOf<String>()
            var minTtl = Long.MAX_VALUE

            for (i in 0 until answers.length()) {
                val answer = answers.getJSONObject(i)
                val ansType = answer.optInt("type")
                val data = answer.optString("data", "")
                if (ansType == DNS_TYPE_A && isValidIPv4(data)) {
                    addresses.add(data)
                    minTtl = minOf(minTtl, answer.optLong("TTL", config.minTtlSeconds))
                } else if (ansType == DNS_TYPE_AAAA && isValidIPv6(data)) {
                    addresses.add(data)
                    minTtl = minOf(minTtl, answer.optLong("TTL", config.minTtlSeconds))
                }
            }

            if (addresses.isEmpty()) throw Exception("No ${typeParam} records in JSON response")

            return DnsRecord(
                hostname = hostname,
                addresses = addresses,
                ttlSeconds = if (minTtl == Long.MAX_VALUE) config.minTtlSeconds else minTtl,
                resolvedAtMillis = System.currentTimeMillis()
            )
        } finally {
            conn.disconnect()
        }
    }

    // --- DNS Wire Format (RFC 1035 + EDNS0 RFC 6891 + padding RFC 8467) ---

    internal fun buildDnsWireQuery(hostname: String, queryType: Int = DNS_TYPE_A): ByteArray {
        val baos = ByteArrayOutputStream()

        // Header: ID=0 (RFC 8484 §4.1), RD=1, QDCOUNT=1, ARCOUNT=1
        baos.write(0x00); baos.write(0x00) // ID
        baos.write(0x01); baos.write(0x00) // Flags: RD=1
        baos.write(0x00); baos.write(0x01) // QDCOUNT
        baos.write(0x00); baos.write(0x00) // ANCOUNT
        baos.write(0x00); baos.write(0x00) // NSCOUNT
        baos.write(0x00); baos.write(0x01) // ARCOUNT

        // Question: IDN-safe label encoding
        val asciiHostname = IDN.toASCII(hostname)
        for (label in asciiHostname.split(".")) {
            val labelBytes = label.toByteArray(Charsets.US_ASCII)
            require(labelBytes.size in 1..63) {
                "DNS label must be 1-63 bytes, got ${labelBytes.size} for '$label'"
            }
            baos.write(labelBytes.size)
            baos.write(labelBytes)
        }
        baos.write(0x00) // root
        baos.write((queryType shr 8) and 0xFF); baos.write(queryType and 0xFF) // QTYPE
        baos.write(0x00); baos.write(0x01) // QCLASS IN

        // EDNS0 OPT (RFC 6891): root name, TYPE=41, UDP=4096, RCODE=0, ver=0
        baos.write(0x00)
        baos.write(0x00); baos.write(0x29) // OPT
        baos.write(0x10); baos.write(0x00) // UDP 4096
        baos.write(0x00); baos.write(0x00); baos.write(0x00); baos.write(0x00) // RCODE+ver+flags

        // Padding (RFC 8467): pad to 128-byte boundary
        val sizeBeforeRdataLen = baos.size()
        val fixedOverhead = 2 + 4 // RDATA len field + padding option header
        val currentTotal = sizeBeforeRdataLen + fixedOverhead
        val paddingNeeded = ((128 - (currentTotal % 128)) % 128)
        val rdataLength = 4 + paddingNeeded

        baos.write((rdataLength shr 8) and 0xFF); baos.write(rdataLength and 0xFF) // RDATA len
        baos.write(0x00); baos.write(0x0C) // Padding option code=12
        baos.write((paddingNeeded shr 8) and 0xFF); baos.write(paddingNeeded and 0xFF) // Padding len
        for (i in 0 until paddingNeeded) {
            baos.write(0x00)
        }

        return baos.toByteArray()
    }

    internal fun parseDnsWireResponse(
        hostname: String,
        data: ByteArray,
        expectedType: Int = DNS_TYPE_A
    ): DnsRecord {
        if (data.size < 12) throw Exception("DNS response too short")

        // Check RCODE in flags (lower 4 bits of byte 3)
        val rcode = data[3].toInt() and 0x0F
        if (rcode != 0) throw Exception("DNS response RCODE=$rcode (expected NOERROR)")

        val qdcount = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        val ancount = ((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)

        // Skip question section
        var offset = 12
        for (i in 0 until qdcount) {
            offset = skipDnsName(data, offset)
            offset += 4 // QTYPE (2) + QCLASS (2)
        }

        // Parse answer records
        val addresses = mutableListOf<String>()
        var minTtl = Long.MAX_VALUE

        for (i in 0 until ancount) {
            offset = skipDnsName(data, offset)
            if (offset + 10 > data.size) break

            val type = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
            // skip class (2 bytes)
            val ttl = ((data[offset + 4].toLong() and 0xFF) shl 24) or
                    ((data[offset + 5].toLong() and 0xFF) shl 16) or
                    ((data[offset + 6].toLong() and 0xFF) shl 8) or
                    (data[offset + 7].toLong() and 0xFF)
            val rdlength = ((data[offset + 8].toInt() and 0xFF) shl 8) or (data[offset + 9].toInt() and 0xFF)
            offset += 10

            if (type == DNS_TYPE_A && rdlength == 4 && offset + 4 <= data.size) {
                val ip = "${data[offset].toInt() and 0xFF}.${data[offset + 1].toInt() and 0xFF}." +
                        "${data[offset + 2].toInt() and 0xFF}.${data[offset + 3].toInt() and 0xFF}"
                if (isPublicAddress(ip)) {
                    addresses.add(ip)
                    minTtl = minOf(minTtl, ttl)
                }
            } else if (type == DNS_TYPE_AAAA && rdlength == 16 && offset + 16 <= data.size) {
                val ipBytes = data.copyOfRange(offset, offset + 16)
                val addr = InetAddress.getByAddress(ipBytes)
                val ip = addr.hostAddress ?: continue
                if (isPublicAddress(ip)) {
                    addresses.add(ip)
                    minTtl = minOf(minTtl, ttl)
                }
            }

            offset += rdlength
        }

        val typeName = if (expectedType == DNS_TYPE_AAAA) "AAAA" else "A"
        if (addresses.isEmpty()) throw Exception("No $typeName records in DNS wire response")

        return DnsRecord(
            hostname = hostname,
            addresses = addresses,
            ttlSeconds = if (minTtl == Long.MAX_VALUE) config.minTtlSeconds else minTtl,
            resolvedAtMillis = System.currentTimeMillis()
        )
    }

    private fun skipDnsName(data: ByteArray, startOffset: Int): Int {
        var offset = startOffset
        var jumps = 0
        while (offset < data.size) {
            val len = data[offset].toInt() and 0xFF
            if (len == 0) {
                return offset + 1
            }
            if ((len and 0xC0) == 0xC0) {
                // Pointer (2 bytes)
                if (offset + 1 >= data.size) throw Exception("Truncated DNS pointer")
                return offset + 2
            }
            offset += 1 + len
            if (++jumps > 128) throw Exception("DNS name too long or pointer loop")
        }
        throw Exception("DNS name extends beyond packet")
    }

    /** TCP connect to a known-good IPv6 address. Fails if IPv6 is blocked upstream. */
    private fun probeIpv6(): Boolean {
        val target = InetSocketAddress(
            InetAddress.getByName(IPV6_PROBE_ADDRESS), IPV6_PROBE_PORT
        )
        var successes = 0
        for (i in 0 until IPV6_PROBE_ATTEMPTS) {
            try {
                Socket().use { sock ->
                    sock.connect(target, IPV6_PROBE_TIMEOUT_MS)
                    successes++
                }
            } catch (_: Exception) { /* TCP handshake failed — IPv6 unreachable */ }
        }
        val available = successes >= IPV6_PROBE_THRESHOLD
        Log.d(TAG, "IPv6 probe: $successes/$IPV6_PROBE_ATTEMPTS succeeded, available=$available")
        return available
    }

    companion object {
        private const val TAG = "DohResolver"
        private const val DNS_TYPE_A = 1
        private const val DNS_TYPE_AAAA = 28
        private const val MAX_DNS_RESPONSE_SIZE = 65536
        private val SAFE_HOSTNAME = Regex("""^[a-zA-Z0-9._-]+$""")
        private val IPV4_PATTERN = Regex("""\d{1,3}(\.\d{1,3}){3}""")
        private const val IPV6_PROBE_ADDRESS = "2001:4860:4860::8888"
        private const val IPV6_PROBE_PORT = 443
        private const val IPV6_PROBE_TIMEOUT_MS = 2000
        private const val IPV6_PROBE_ATTEMPTS = 3
        private const val IPV6_PROBE_THRESHOLD = 2
    }
}
