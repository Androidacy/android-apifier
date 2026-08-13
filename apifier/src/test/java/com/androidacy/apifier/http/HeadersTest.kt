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

import org.junit.Assert.assertEquals
import org.junit.Test

class HeadersTest {

    @Test
    fun headerLookupIsCaseInsensitiveLastWins() {
        val headers = Headers.Builder()
            .add("X-A", "1")
            .add("x-a", "2")
            .build()

        assertEquals("2", headers["X-A"])
        assertEquals("2", headers["x-A"])
        assertEquals(listOf("1", "2"), headers.values("X-A"))
        assertEquals(2, headers.size)
        assertEquals(setOf("X-A"), headers.names())
    }

    @Test
    fun headerSetReplacesAddAppends() {
        val headers = Headers.Builder()
            .add("Accept", "text/plain")
            .add("accept", "text/html")
            .set("ACCEPT", "application/json")
            .build()

        assertEquals(listOf("application/json"), headers.values("Accept"))
        assertEquals(1, headers.size)
    }

    @Test
    fun removeAllDropsEveryCasing() {
        val headers = Headers.Builder()
            .add("A", "1")
            .add("a", "2")
            .add("B", "3")
            .removeAll("A")
            .build()

        assertEquals(1, headers.size)
        assertEquals("B", headers.name(0))
        assertEquals("3", headers.value(0))
    }

    @Test
    fun headersOfRejectsOddArgumentCount() {
        val failure = runCatching { Headers.headersOf("A", "1", "B") }.exceptionOrNull()

        assertEquals(IllegalArgumentException::class.java, failure?.javaClass)
    }
}
