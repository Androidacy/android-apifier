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

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringSetPreferencesKey
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking

/**
 * [CookieStorage] backed by Jetpack DataStore Preferences.
 *
 * Bridges DataStore's async API to the synchronous [CookieStorage] contract
 * using [runBlocking]. OkHttp calls cookie methods from its own IO threads,
 * so this is safe as long as the client isn't built on the main thread.
 *
 * Requires `androidx.datastore:datastore-preferences` on the consumer's classpath.
 */
class DataStoreCookieStorage(
    private val dataStore: DataStore<Preferences>
) : CookieStorage {

    override fun getStringSet(key: String, defaultValue: Set<String>?): Set<String>? {
        return runBlocking {
            dataStore.data.first()[stringSetPreferencesKey(key)] ?: defaultValue
        }
    }

    override fun putStringSet(key: String, value: Set<String>) {
        runBlocking {
            dataStore.edit { it[stringSetPreferencesKey(key)] = value }
        }
    }

    override fun remove(key: String) {
        runBlocking {
            dataStore.edit { it.remove(stringSetPreferencesKey(key)) }
        }
    }
}
