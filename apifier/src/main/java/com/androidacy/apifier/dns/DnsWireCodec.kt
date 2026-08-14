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

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.IDN
import java.net.InetAddress

/**
 * Addresses parsed out of one DNS response, exactly as the server sent them.
 * An empty list means the server answered authoritatively with no records.
 */
data class DnsAnswer(val addresses: List<String>, val minTtlSeconds: Long)

/** A response that could not be turned into a [DnsAnswer], categorized by [kind]. */
class DnsParseException(val kind: Kind, message: String) : IOException(message) {
    enum class Kind { NXDOMAIN, SERVER_ERROR, INVALID }
}

/** RFC 1035 wire format with EDNS0 (RFC 6891) and padding (RFC 8467). */
internal object DnsWireCodec {

    const val TYPE_A = 1
    const val TYPE_AAAA = 28

    /** Builds a query for [hostname] of record [type], padded to a 128-byte boundary. */
    fun buildQuery(hostname: String, type: Int): ByteArray {
        val out = ByteArrayOutputStream()

        // Header: ID=0 (RFC 8484 4.1), RD=1, QDCOUNT=1, ARCOUNT=1
        out.write(0x00); out.write(0x00)
        out.write(0x01); out.write(0x00)
        out.write(0x00); out.write(0x01)
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x01)

        for (label in IDN.toASCII(hostname).split(".")) {
            val labelBytes = label.toByteArray(Charsets.US_ASCII)
            require(labelBytes.size in 1..63) {
                "DNS label must be 1-63 bytes, got ${labelBytes.size} for '$label'"
            }
            out.write(labelBytes.size)
            out.write(labelBytes)
        }
        out.write(0x00)
        out.write((type shr 8) and 0xFF); out.write(type and 0xFF)
        out.write(0x00); out.write(0x01)

        // EDNS0 OPT: root name, TYPE=41, UDP payload 4096, RCODE+version+flags all zero
        out.write(0x00)
        out.write(0x00); out.write(0x29)
        out.write(0x10); out.write(0x00)
        out.write(0x00); out.write(0x00); out.write(0x00); out.write(0x00)

        val fixedOverhead = 2 + 4 // RDATA length field plus the padding option header
        val paddingNeeded = (128 - ((out.size() + fixedOverhead) % 128)) % 128
        val rdataLength = 4 + paddingNeeded

        out.write((rdataLength shr 8) and 0xFF); out.write(rdataLength and 0xFF)
        out.write(0x00); out.write(0x0C)
        out.write((paddingNeeded shr 8) and 0xFF); out.write(paddingNeeded and 0xFF)
        repeat(paddingNeeded) { out.write(0x00) }

        return out.toByteArray()
    }

    /**
     * Parses every A and AAAA record in [data]. Addresses are returned unfiltered: the trust
     * verdict has to see a non-routable answer to recognize it as interception, so dropping
     * one here would hide the evidence.
     */
    fun parseResponse(data: ByteArray): DnsAnswer {
        if (data.size < 12) {
            throw DnsParseException(DnsParseException.Kind.INVALID, "DNS response too short")
        }

        val rcode = data[3].toInt() and 0x0F
        if (rcode == 3) {
            throw DnsParseException(DnsParseException.Kind.NXDOMAIN, "DNS response RCODE=3")
        }
        if (rcode != 0) {
            throw DnsParseException(DnsParseException.Kind.SERVER_ERROR, "DNS response RCODE=$rcode")
        }

        val qdcount = readUShort(data, 4)
        val ancount = readUShort(data, 6)

        var offset = 12
        repeat(qdcount) {
            offset = skipName(data, offset) + 4 // QTYPE + QCLASS
        }

        val addresses = mutableListOf<String>()
        var minTtl = Long.MAX_VALUE

        repeat(ancount) {
            offset = skipName(data, offset)
            if (offset + 10 > data.size) {
                throw DnsParseException(DnsParseException.Kind.INVALID, "Answer record beyond packet")
            }
            val type = readUShort(data, offset)
            val ttl = (readUShort(data, offset + 4).toLong() shl 16) or readUShort(data, offset + 6).toLong()
            val rdlength = readUShort(data, offset + 8)
            offset += 10
            if (offset + rdlength > data.size) {
                throw DnsParseException(DnsParseException.Kind.INVALID, "Record data beyond packet")
            }

            if (type == TYPE_A && rdlength == 4) {
                addresses.add(
                    "${data[offset].toInt() and 0xFF}.${data[offset + 1].toInt() and 0xFF}." +
                        "${data[offset + 2].toInt() and 0xFF}.${data[offset + 3].toInt() and 0xFF}"
                )
                minTtl = minOf(minTtl, ttl)
            } else if (type == TYPE_AAAA && rdlength == 16) {
                val address = InetAddress.getByAddress(data.copyOfRange(offset, offset + 16))
                address.hostAddress?.let {
                    addresses.add(it)
                    minTtl = minOf(minTtl, ttl)
                }
            }

            offset += rdlength
        }

        return DnsAnswer(addresses, if (minTtl == Long.MAX_VALUE) 0 else minTtl)
    }

    private fun readUShort(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    private fun skipName(data: ByteArray, startOffset: Int): Int {
        var offset = startOffset
        var labels = 0
        while (offset < data.size) {
            val length = data[offset].toInt() and 0xFF
            if (length == 0) return offset + 1
            if ((length and 0xC0) == 0xC0) {
                if (offset + 1 >= data.size) {
                    throw DnsParseException(DnsParseException.Kind.INVALID, "Truncated DNS pointer")
                }
                return offset + 2
            }
            offset += 1 + length
            if (++labels > 128) {
                throw DnsParseException(DnsParseException.Kind.INVALID, "DNS name too long or pointer loop")
            }
        }
        throw DnsParseException(DnsParseException.Kind.INVALID, "DNS name extends beyond packet")
    }
}
