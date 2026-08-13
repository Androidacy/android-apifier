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

/**
 * An ordered list of HTTP header fields.
 *
 * Duplicate names are kept in the order they were added, matching how HTTP allows a field to
 * repeat. Lookup by name is case-insensitive and [get] returns the last matching value, which
 * is what a server's final `Set-Cookie` or `Content-Type` wins rule expects.
 */
class Headers private constructor(private val namesAndValues: List<String>) {

    val size: Int get() = namesAndValues.size / 2

    fun name(index: Int): String = namesAndValues[index * 2]

    fun value(index: Int): String = namesAndValues[index * 2 + 1]

    /** The last value for [name], or null when the header is absent. */
    operator fun get(name: String): String? {
        for (index in size - 1 downTo 0) {
            if (name(index).equals(name, ignoreCase = true)) return value(index)
        }
        return null
    }

    /** Every value for [name], in the order they appear. */
    fun values(name: String): List<String> =
        (0 until size).filter { name(it).equals(name, ignoreCase = true) }.map { value(it) }

    /** The distinct header names, compared without case. */
    fun names(): Set<String> {
        val result = sortedSetOf<String>(String.CASE_INSENSITIVE_ORDER)
        for (index in 0 until size) result.add(name(index))
        return result
    }

    fun asList(): List<Pair<String, String>> = (0 until size).map { name(it) to value(it) }

    fun newBuilder(): Builder = Builder(namesAndValues.toMutableList())

    override fun toString(): String = buildString {
        for (index in 0 until size) append(name(index)).append(": ").append(value(index)).append('\n')
    }

    override fun equals(other: Any?): Boolean = other is Headers && other.namesAndValues == namesAndValues

    override fun hashCode(): Int = namesAndValues.hashCode()

    class Builder internal constructor(private val namesAndValues: MutableList<String>) {

        constructor() : this(mutableListOf())

        /** Appends [name]: [value], keeping any existing values for the same name. */
        fun add(name: String, value: String): Builder = apply {
            checkNameAndValue(name, value)
            namesAndValues.add(name)
            namesAndValues.add(value)
        }

        /** Replaces every existing value for [name] with [value]. */
        fun set(name: String, value: String): Builder = apply {
            checkNameAndValue(name, value)
            removeAll(name)
            namesAndValues.add(name)
            namesAndValues.add(value)
        }

        fun removeAll(name: String): Builder = apply {
            var index = 0
            while (index < namesAndValues.size) {
                if (namesAndValues[index].equals(name, ignoreCase = true)) {
                    namesAndValues.removeAt(index)
                    namesAndValues.removeAt(index)
                } else {
                    index += 2
                }
            }
        }

        fun build(): Headers = Headers(namesAndValues.toList())

        private fun checkNameAndValue(name: String, value: String) {
            require(name.isNotEmpty()) { "header name is empty" }
            // A line terminator in either half would let a caller-supplied string forge extra
            // header lines once the request is serialized.
            require(name.none { it in FORBIDDEN_IN_NAME }) {
                "header name contains a forbidden character: $name"
            }
            require(value.none { it in FORBIDDEN_IN_VALUE }) {
                "value for header $name contains a forbidden character"
            }
        }

        private companion object {
            const val FORBIDDEN_IN_VALUE = "\n\r\u0000"
            const val FORBIDDEN_IN_NAME = FORBIDDEN_IN_VALUE + " \t:"
        }
    }

    companion object {
        @JvmStatic
        fun headersOf(vararg namesAndValues: String): Headers {
            require(namesAndValues.size % 2 == 0) { "expected alternating names and values" }
            val builder = Builder()
            for (index in namesAndValues.indices step 2) {
                builder.add(namesAndValues[index], namesAndValues[index + 1])
            }
            return builder.build()
        }

        @JvmStatic
        fun of(pairs: List<Pair<String, String>>): Headers {
            val builder = Builder()
            for ((name, value) in pairs) builder.add(name, value)
            return builder.build()
        }
    }
}
