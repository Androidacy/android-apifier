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
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
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

    /**
     * Race resolved addresses per domain to pick the best reachable IP for
     * HostResolverRules. Must be called after [preResolve]. All domains are
     * raced in parallel. Each domain follows RFC 8305 Happy Eyeballs v2:
     * addresses are interleaved by family (v6, v4, v6, v4...), then
     * connection attempts are staggered with [CONNECTION_ATTEMPT_DELAY_MS]
     * between each. All attempts run concurrently; first TCP connect wins.
     * The winner is reordered to the front of the cache entry so
     * [buildHostResolverRules] picks it.
     */
    fun raceResolvedAddresses(port: Int = 443) {
        val candidates = cache.values.filter { record ->
            record.addresses.any { it.contains(':') } &&
                record.addresses.any { !it.contains(':') }
        }
        if (candidates.isEmpty()) return

        val threads = candidates.map { record ->
            Thread({
                val winner = happyEyeballs(record.addresses, port)
                if (winner != null) {
                    val reordered = listOf(winner) + record.addresses.filter { it != winner }
                    cacheRecord(record.copy(addresses = reordered))
                }
            }, "HE-${record.hostname}").also { it.start() }
        }
        threads.forEach { it.join() }
    }

    /**
     * RFC 8305 Happy Eyeballs v2 connection racing.
     *
     * 1. **Interleave** (Section 4): Build sorted list alternating address
     *    families — [FIRST_ADDRESS_FAMILY_COUNT] IPv6 addresses first, then
     *    one IPv4, then one IPv6, etc.
     * 2. **Staggered starts** (Section 5): Launch connection attempts in
     *    list order with [CONNECTION_ATTEMPT_DELAY_MS] between each.
     *    Previous attempts are NOT cancelled — all run in parallel.
     * 3. **First wins**: First successful TCP connect sets the winner.
     *    All remaining attempts are interrupted.
     *
     * Returns the winning address, or IPv4 fallback if all fail.
     */
    private fun happyEyeballs(addresses: List<String>, port: Int): String? {
        val v6Addrs = addresses.filter { it.contains(':') }
        val v4Addrs = addresses.filter { !it.contains(':') }

        if (v6Addrs.isEmpty()) return v4Addrs.firstOrNull()
        if (v4Addrs.isEmpty()) return v6Addrs.firstOrNull()

        // Section 4: Interleave with First Address Family Count = 1
        // Result: v6_0, v4_0, v6_1, v4_1, ...
        val interleaved = buildInterleavedList(v6Addrs, v4Addrs)

        val winner = AtomicReference<String>(null)
        val latch = CountDownLatch(1)
        val attemptThreads = mutableListOf<Thread>()

        // Keep socket refs so we can close them directly (Thread.interrupt
        // may not unblock Socket.connect on all Android implementations).
        val openSockets = ConcurrentHashMap<Int, Socket>()

        // Section 5: Staggered connection attempts
        for ((index, addr) in interleaved.withIndex()) {
            if (winner.get() != null) break

            val idx = index
            val thread = Thread({
                val sock = Socket()
                openSockets[idx] = sock
                try {
                    sock.connect(
                        InetSocketAddress(InetAddress.getByName(addr), port),
                        RACE_CONNECT_TIMEOUT_MS
                    )
                    if (winner.compareAndSet(null, addr)) latch.countDown()
                } catch (_: Exception) {
                    // This address unreachable
                } finally {
                    try { sock.close() } catch (_: Exception) {}
                    openSockets.remove(idx)
                }
            }, "HE-${addr.take(15)}-$idx")

            attemptThreads.add(thread)
            thread.start()

            // Wait CONNECTION_ATTEMPT_DELAY_MS before next attempt,
            // stop early if we already have a winner (Section 5)
            if (index < interleaved.lastIndex) {
                try {
                    if (latch.await(CONNECTION_ATTEMPT_DELAY_MS, TimeUnit.MILLISECONDS)) break
                } catch (_: InterruptedException) {
                    break
                }
            }
        }

        // Wait for a winner or overall timeout
        if (winner.get() == null) {
            val remaining = RACE_CONNECT_TIMEOUT_MS + 500L
            latch.await(remaining, TimeUnit.MILLISECONDS)
        }

        // Force-close lingering sockets and interrupt threads
        openSockets.values.forEach { try { it.close() } catch (_: Exception) {} }
        attemptThreads.forEach { it.interrupt() }

        // Section 5: if all fail, prefer IPv4 as universally routable fallback
        return winner.get() ?: v4Addrs.first()
    }

    /**
     * RFC 8305 Section 4: Build interleaved address list.
     * [FIRST_ADDRESS_FAMILY_COUNT] preferred-family (IPv6) addresses first,
     * then alternate one-for-one with the other family.
     */
    private fun buildInterleavedList(
        v6Addrs: List<String>,
        v4Addrs: List<String>
    ): List<String> {
        val result = mutableListOf<String>()
        val v6Iter = v6Addrs.iterator()
        val v4Iter = v4Addrs.iterator()

        // Leading preferred-family addresses
        repeat(FIRST_ADDRESS_FAMILY_COUNT) {
            if (v6Iter.hasNext()) result.add(v6Iter.next())
        }

        // Alternate families one-for-one
        while (v6Iter.hasNext() || v4Iter.hasNext()) {
            if (v4Iter.hasNext()) result.add(v4Iter.next())
            if (v6Iter.hasNext()) result.add(v6Iter.next())
        }

        return result
    }

    fun buildHostResolverRules(): String? {
        if (cache.isEmpty()) return null
        val rules = cache.values
            .filter { record -> SAFE_HOSTNAME.matches(record.hostname) }
            .joinToString(", ") { record ->
                // After raceResolvedAddresses(), the race winner is
                // reordered to front. For unraced records (single family),
                // .first() returns the only available address.
                val ip = record.addresses.first()
                // Chromium's HostResolverRules parser (ParseHostAndPort)
                // requires bracketed IPv6 — unbracketed addresses are
                // misparsed (last colon treated as host:port separator).
                val host = if (':' in ip) "[$ip]" else ip
                "MAP ${record.hostname} $host"
            }
        return rules.ifEmpty { null }
    }

    fun preResolve(domains: List<String>) {
        if (domains.size <= 1) {
            domains.forEach { resolve(it) }
            return
        }
        val threads = domains.map { domain ->
            Thread({ resolve(domain) }, "DoH-Resolve-$domain").also { it.start() }
        }
        threads.forEach { it.join() }
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
    }

    private fun queryProvider(provider: DohProvider, hostname: String): DnsRecord? {
        // Only query AAAA if IPv6 is reachable
        val v6Record = if (ipv6Available) {
            try {
                querySingleType(provider, hostname, DNS_TYPE_AAAA)
            } catch (e: Exception) {
                Log.d(TAG, "AAAA query failed for ${provider.name}/$hostname: ${e.message}")
                null
            }
        } else null

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

        // RFC 8305 Happy Eyeballs v2 constants

        /** Section 4: Number of leading preferred-family (IPv6) addresses
         *  before interleaving with IPv4. RFC recommends 1. */
        private const val FIRST_ADDRESS_FAMILY_COUNT = 1

        /** Section 5: Delay between staggered connection attempts.
         *  RFC recommends 250ms (min 100ms, max 2s). */
        private const val CONNECTION_ATTEMPT_DELAY_MS = 250L

        /** Per-address TCP connect timeout during the race. Matches the
         *  RFC maximum Connection Attempt Delay of 2 seconds. */
        private const val RACE_CONNECT_TIMEOUT_MS = 2000
    }
}
