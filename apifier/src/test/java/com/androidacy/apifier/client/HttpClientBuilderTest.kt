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

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.chromium.net.CronetEngine
import org.chromium.net.CronetProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
@Config(shadows = [ShadowCronetProvider::class])
class HttpClientBuilderTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        ShadowCronetProvider.providers = emptyList()
    }

    private fun buildWith(vararg providers: CronetProvider, config: NetworkConfig = NetworkConfig()): HttpClientBuilder {
        ShadowCronetProvider.providers = providers.toList()
        val builder = HttpClientBuilder(context, config)
        runCatching { builder.build() }
        return builder
    }

    @Test
    fun theLadderPrefersTheFirstEligibleProvider() {
        val fallback = FakeCronetProvider(context, CronetProvider.PROVIDER_NAME_FALLBACK, "1.0")
        val appPackaged = FakeCronetProvider(context, CronetProvider.PROVIDER_NAME_APP_PACKAGED, "1.0")
        val builder = buildWith(fallback, appPackaged)

        assertEquals("IN_USE", builder.providerReport["App-Packaged-Cronet-Provider:1.0"])
        // the ladder stops at the first eligible match, so the lower-priority fallback rung is never recorded
        assertFalse(builder.providerReport.containsKey(CronetProvider.PROVIDER_NAME_FALLBACK))
    }

    @Test
    fun anUnderVersionProviderIsReportedTooOld() {
        val gms = FakeCronetProvider(context, "Google-Play-Services-Cronet-Provider", "100.0.0.0")
        val builder = buildWith(gms)

        assertEquals("TOO_OLD", builder.providerReport["Google-Play-Services-Cronet-Provider:100.0.0.0"])
    }

    @Test
    fun isAtLeastAcceptsAnExactMatch() {
        val gms = FakeCronetProvider(context, "Google-Play-Services-Cronet-Provider", "141.0.7340.3")
        val builder = buildWith(gms)

        assertEquals("IN_USE", builder.providerReport["Google-Play-Services-Cronet-Provider:141.0.7340.3"])
    }

    @Test
    fun isAtLeastComparesSegmentwise() {
        val gms = FakeCronetProvider(context, "Google-Play-Services-Cronet-Provider", "141.0.7340.10")
        val builder = buildWith(gms)

        assertEquals("IN_USE", builder.providerReport["Google-Play-Services-Cronet-Provider:141.0.7340.10"])
    }

    @Test
    fun isAtLeastHandlesUnequalSegmentCounts() {
        val gms = FakeCronetProvider(context, "Google-Play-Services-Cronet-Provider", "141.0")
        val builder = buildWith(gms)

        assertEquals("TOO_OLD", builder.providerReport["Google-Play-Services-Cronet-Provider:141.0"])
    }

    @Test
    fun anUnusableCacheDirectoryAbortsEngineConstruction() {
        val blockedParent = File.createTempFile("cronet-cache-parent", "")
        val cacheDir = File(blockedParent, "cache")
        val fallback = FakeCronetProvider(context, CronetProvider.PROVIDER_NAME_FALLBACK, "1.0", realEngine = true)
        ShadowCronetProvider.providers = listOf(fallback)
        val httpClientBuilder = HttpClientBuilder(
            context,
            NetworkConfig(
                cronetConfig = CronetConfig(
                    enableQuic = false,
                    enableBuiltInDnsResolver = false,
                    cacheDirectory = cacheDir
                )
            )
        )

        assertThrows(IOException::class.java) { httpClientBuilder.build() }
        assertEquals("IN_USE", httpClientBuilder.providerReport["${CronetProvider.PROVIDER_NAME_FALLBACK}:1.0"])

        blockedParent.delete()
    }
}

/**
 * Redirects Cronet's own reflective provider discovery to a fixed list, since Robolectric can
 * neither resolve the GMS provider nor probe for native ones.
 */
@Implements(CronetProvider::class)
class ShadowCronetProvider {
    companion object {
        var providers: List<CronetProvider> = emptyList()

        @Implementation
        @JvmStatic
        fun getAllProviders(context: Context): List<CronetProvider> = providers
    }
}

private class FakeCronetProvider(
    context: Context,
    private val providerName: String,
    private val providerVersion: String?,
    private val realEngine: Boolean = false
) : CronetProvider(context) {
    private val delegate: CronetProvider? = if (realEngine) {
        Class.forName("org.chromium.net.impl.JavaCronetProvider")
            .getConstructor(Context::class.java)
            .newInstance(context) as CronetProvider
    } else {
        null
    }

    override fun createBuilder(): CronetEngine.Builder =
        delegate?.createBuilder() ?: throw UnsupportedOperationException("not needed for this test")

    override fun getName(): String = providerName
    override fun getVersion(): String = providerVersion ?: throw IllegalStateException("no version")
    override fun isEnabled(): Boolean = true
}
