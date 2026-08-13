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

import java.nio.charset.Charset
import java.nio.charset.IllegalCharsetNameException
import java.nio.charset.UnsupportedCharsetException

/**
 * An RFC 2045 media type, as carried by `Content-Type`.
 *
 * [type] and [subtype] are lowercased for comparison while [toString] returns the literal the
 * value was parsed from, so a header round-trips byte for byte.
 */
class MediaType private constructor(
    private val literal: String,
    val type: String,
    val subtype: String,
    val charset: Charset?
) {

    override fun toString(): String = literal

    override fun equals(other: Any?): Boolean = other is MediaType && other.literal == literal

    override fun hashCode(): Int = literal.hashCode()

    companion object {
        private val TOKEN = Regex("[a-zA-Z0-9!#$%&'*+._^`|~-]+")

        /**
         * Parses [this] as a media type, or returns null when it is not `type/subtype` with
         * optional `; name=value` parameters. A `charset` parameter naming an encoding this
         * JVM does not have leaves [charset] null rather than failing the whole parse.
         */
        @JvmStatic
        @JvmName("parseOrNull")
        fun String.toMediaTypeOrNull(): MediaType? {
            val parts = split(';')
            val typeAndSubtype = parts[0].trim().split('/')
            if (typeAndSubtype.size != 2) return null
            val (type, subtype) = typeAndSubtype
            if (!TOKEN.matches(type) || !TOKEN.matches(subtype)) return null

            var charset: Charset? = null
            for (parameter in parts.drop(1)) {
                val separator = parameter.indexOf('=')
                if (separator == -1) continue
                val name = parameter.substring(0, separator).trim()
                if (!name.equals("charset", ignoreCase = true)) continue
                val value = parameter.substring(separator + 1).trim().removeSurrounding("\"")
                charset = try {
                    Charset.forName(value)
                } catch (_: IllegalCharsetNameException) {
                    null
                } catch (_: UnsupportedCharsetException) {
                    null
                }
            }

            return MediaType(this, type.lowercase(), subtype.lowercase(), charset)
        }
    }
}
