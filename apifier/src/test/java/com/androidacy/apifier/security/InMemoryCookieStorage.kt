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

/** In-memory [CookieStorage] test double, backed by a plain map. Test-only. */
class InMemoryCookieStorage : CookieStorage {

    private val map = mutableMapOf<String, Set<String>>()

    override fun getStringSet(key: String, defaultValue: Set<String>?): Set<String>? =
        map[key]?.toSet() ?: defaultValue

    override fun putStringSet(key: String, value: Set<String>) {
        map[key] = value.toSet()
    }

    override fun remove(key: String) {
        map.remove(key)
    }
}
