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

/** Backing store for cookie persistence. Implement via SharedPreferences, EncryptedSharedPreferences, etc. */
interface CookieStorage {
    /** Returns the set stored under [key], or [defaultValue] if absent. */
    fun getStringSet(key: String, defaultValue: Set<String>?): Set<String>?

    /** Writes [value] under [key], replacing any existing entry. */
    fun putStringSet(key: String, value: Set<String>)

    /** Deletes the entry for [key]. */
    fun remove(key: String)
}
