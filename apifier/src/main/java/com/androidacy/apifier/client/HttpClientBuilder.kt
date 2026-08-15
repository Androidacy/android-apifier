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
@file:Suppress("DEPRECATION")

package com.androidacy.apifier.client

import android.content.Context
import android.os.Looper
import android.util.Log
import com.google.android.gms.net.CronetProviderInstaller
import com.google.android.gms.tasks.Tasks
import org.chromium.net.CronetEngine
import org.chromium.net.CronetProvider
import org.chromium.net.DnsOptions
import org.chromium.net.QuicOptions
import java.io.IOException

/** Selects a Cronet provider and builds the engine the transport runs on. */
class HttpClientBuilder(
    private val context: Context,
    private val config: NetworkConfig
) {
    companion object {
        private const val TAG = "HttpClientBuilder"

        internal const val PROVIDER_IN_USE = "IN_USE"
        internal const val PROVIDER_TOO_OLD = "TOO_OLD"
        internal const val PROVIDER_INELIGIBLE_PLAT = "INELIGIBLE_PLAT"
        internal const val PROVIDER_FAILED = "FAILED"
        internal const val PROVIDER_NOT_PRESENT = "NOT_PRESENT"

        private const val GMS_PROVIDER_NAME = "Google-Play-Services-Cronet-Provider"
        private const val JAVA_PROVIDER_CLASS = "org.chromium.net.impl.JavaCronetProvider"

        /** Lightweight freshness guard, not a compatibility floor. */
        private const val MIN_ENGINE_VERSION = "141.0.7340.3"

        private fun isAtLeast(version: String, minimum: String): Boolean {
            val actual = version.split('.')
            val floor = minimum.split('.')
            for (i in 0 until maxOf(actual.size, floor.size)) {
                val a = actual.getOrNull(i)?.toIntOrNull() ?: 0
                val f = floor.getOrNull(i)?.toIntOrNull() ?: 0
                if (a != f) return a > f
            }
            return true
        }
    }

    /**
     * Provider selection outcome in ladder order. Keys are `name:version`, or the bare name
     * when the version could not be read. Empty until [build] runs.
     */
    internal var providerReport: Map<String, String> = emptyMap()
        private set

    fun build(): CronetEngine {
        if (Looper.getMainLooper().isCurrentThread) {
            Log.d(TAG, "Constructed on the main thread; provider I/O may be skipped")
        }
        return buildEngine()
    }

    private fun consider(
        providers: List<CronetProvider>,
        name: String,
        absentStatus: String,
        minVersion: String?,
        report: MutableMap<String, String>
    ): CronetProvider? {
        val provider = providers.firstOrNull { it.name == name }
        if (provider == null || !provider.isEnabled) {
            report[name] = absentStatus
            return null
        }
        val version = runCatching { provider.version }.getOrNull()
        if (version == null) {
            report[name] = PROVIDER_FAILED
            return null
        }
        val key = "$name:$version"
        if (minVersion != null && !isAtLeast(version, minVersion)) {
            report[key] = PROVIDER_TOO_OLD
            return null
        }
        report[key] = PROVIDER_IN_USE
        return provider
    }

    private fun selectProvider(report: MutableMap<String, String>): CronetProvider {
        val installed = CronetProvider.getAllProviders(context)
        consider(
            installed, CronetProvider.PROVIDER_NAME_HTTPENGINE_NATIVE,
            PROVIDER_INELIGIBLE_PLAT, MIN_ENGINE_VERSION, report
        )?.let { return it }

        // Deferred past the platform rung: GMS reports disabled until this completes, and it
        // can block on a Dynamite download.
        val withGms = try {
            Tasks.await(CronetProviderInstaller.installProvider(context))
            CronetProvider.getAllProviders(context)
        } catch (e: Exception) {
            installed
        }

        consider(withGms, GMS_PROVIDER_NAME, PROVIDER_NOT_PRESENT, MIN_ENGINE_VERSION, report)
            ?.let { return it }
        consider(withGms, CronetProvider.PROVIDER_NAME_APP_PACKAGED, PROVIDER_NOT_PRESENT, null, report)
            ?.let { return it }
        consider(withGms, CronetProvider.PROVIDER_NAME_FALLBACK, PROVIDER_NOT_PRESENT, null, report)
            ?.let { return it }

        val reflective = runCatching {
            Class.forName(JAVA_PROVIDER_CLASS)
                .getConstructor(Context::class.java)
                .newInstance(context) as CronetProvider
        }.getOrNull() ?: throw IllegalStateException("No Cronet provider available")

        val version = runCatching { reflective.version }.getOrNull()
        report[if (version == null) reflective.name else "${reflective.name}:$version"] = PROVIDER_IN_USE
        return reflective
    }

    @Suppress("UnsafeOptInUsageError", "DEPRECATION")
    private fun buildEngine(): CronetEngine {
        val report = LinkedHashMap<String, String>()
        val provider = selectProvider(report)
        providerReport = report
        Log.i(TAG, "Cronet providers: " + report.entries.joinToString { "${it.key}=${it.value}" })

        val builder = provider.createBuilder().apply {
            enableBrotli(config.cronetConfig.enableBrotli)
            enableHttp2(config.cronetConfig.enableHttp2)
            enableQuic(config.cronetConfig.enableQuic)

            if (config.cronetConfig.enableQuic) {
                setQuicOptions(
                    QuicOptions.builder()
                        .retryWithoutAltSvcOnQuicErrors(true)
                        .enableTlsZeroRtt(config.cronetConfig.enableTlsZeroRtt)
                        .setInMemoryServerConfigsCacheSize(8192)
                        .build()
                )
                config.cronetConfig.quicHints.forEach { (host, port, alternatePort) -> addQuicHint(host, port, alternatePort) }
            }

            if (config.cronetConfig.enableBuiltInDnsResolver) {
                setDnsOptions(
                    DnsOptions.builder()
                        .preestablishConnectionsToStaleDnsResults(config.cronetConfig.enableStaleDns)
                        .enableStaleDns(config.cronetConfig.enableStaleDns)
                        .useBuiltInDnsResolver(true)
                        .persistHostCache(true)
                        .build()
                )
            }

            config.cronetConfig.cacheDirectory?.let { dir ->
                if (!dir.exists() && !dir.mkdirs()) {
                    throw IOException("Failed to create cronet cache directory")
                }
                setStoragePath(dir.absolutePath)
                enableHttpCache(CronetEngine.Builder.HTTP_CACHE_DISK, config.cronetConfig.cacheSizeBytes)
            }

            enablePublicKeyPinningBypassForLocalTrustAnchors(false)
        }

        return builder.build()
    }
}
