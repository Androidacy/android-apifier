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

import android.content.Context
import com.androidacy.apifier.R
import java.net.IDN

/**
 * Longest-match public suffix lookup per the publicsuffix.org rule algorithm.
 *
 * Rules are taken as already comment-stripped, blank-line-stripped, and punycoded (the
 * bundled `R.raw.public_suffix_list` is generated that way). Input domains are normalized
 * to the same punycode form before comparison.
 */
class PublicSuffixList(rules: Sequence<String>) {

    private val exact = HashSet<String>()
    private val wildcard = HashSet<String>()
    private val exception = HashSet<String>()

    init {
        for (line in rules) {
            val rule = line.trim()
            if (rule.isEmpty()) continue
            when {
                rule.startsWith("!") -> exception.add(rule.substring(1))
                rule.startsWith("*.") -> wildcard.add(rule.substring(2))
                else -> exact.add(rule)
            }
        }
    }

    /** True when [domain] is exactly a public suffix, e.g. `"com"` or `"co.uk"`. */
    fun isPublicSuffix(domain: String): Boolean {
        val normalized = normalize(domain) ?: return false
        val labels = normalized.split(".")
        return matchedSuffix(labels).joinToString(".") == normalized
    }

    /**
     * The registrable domain (public suffix plus one leading label), or null when [domain]
     * is itself a public suffix, an IP literal, empty, or has no label above its suffix.
     */
    fun effectiveTldPlusOne(domain: String): String? {
        val normalized = normalize(domain) ?: return null
        val labels = normalized.split(".")
        val suffix = matchedSuffix(labels)
        if (suffix.size >= labels.size) return null
        return labels.subList(labels.size - suffix.size - 1, labels.size).joinToString(".")
    }

    /**
     * Longest matching public suffix for [labels], most labels first. An exception rule
     * match overrides a same-length wildcard match and yields its own label minus one
     * (the label the exception carves out). With nothing matching, the last label stands
     * as the public suffix under the implicit universal `*` rule.
     */
    private fun matchedSuffix(labels: List<String>): List<String> {
        for (start in labels.indices) {
            val candidate = labels.subList(start, labels.size)
            val suffix = candidate.joinToString(".")
            if (suffix in exception) return candidate.subList(1, candidate.size)
            if (suffix in exact) return candidate
            if (candidate.size >= 2 && candidate.subList(1, candidate.size).joinToString(".") in wildcard) {
                return candidate
            }
        }
        return labels.subList(labels.size - 1, labels.size)
    }

    private fun normalize(domain: String): String? {
        if (domain.isEmpty() || isIpLiteral(domain)) return null
        return try {
            IDN.toASCII(domain.lowercase())
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private fun isIpLiteral(host: String): Boolean {
        if (host.contains(":")) return true
        val labels = host.split(".")
        return labels.all { it.isNotEmpty() && it.all(Char::isDigit) }
    }

    companion object {
        /** Loads the bundled list from `R.raw.public_suffix_list`. */
        fun load(context: Context): PublicSuffixList {
            val lines = context.resources.openRawResource(R.raw.public_suffix_list)
                .bufferedReader()
                .use { it.readLines() }
            return PublicSuffixList(lines.asSequence())
        }
    }
}
