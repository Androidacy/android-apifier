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

import java.net.UnknownHostException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ResolverQualificationTest {

    private val pools = mutableListOf<ExecutorService>()

    @After
    fun tearDown() {
        pools.forEach { it.shutdownNow() }
    }

    @Test
    fun aResolverAnsweringInvalidLabelsIsUntrusted() {
        val qualification = qualification { listOf(PUBLIC_ADDRESS) }

        assertEquals(ResolverTrust.UNTRUSTED, qualification.globalTrust())
    }

    @Test
    fun aCanarySinkholedToPrivateSpaceIsUntrusted() {
        val qualification = qualification { host ->
            if (host.endsWith(INVALID_SUFFIX)) throw UnknownHostException(host) else listOf("10.0.0.1")
        }

        assertEquals(ResolverTrust.UNTRUSTED, qualification.globalTrust())
    }

    @Test
    fun aCleanResolverIsTrusted() {
        assertEquals(ResolverTrust.TRUSTED, qualification(resolve = CLEAN_RESOLVE).globalTrust())
    }

    @Test
    fun anAmbiguousLaneRetriesOnceThenFailsClosed() {
        val junkCalls = AtomicInteger()
        val qualification = qualification { host ->
            if (!host.endsWith(INVALID_SUFFIX)) {
                listOf(PUBLIC_ADDRESS)
            } else if (junkCalls.getAndIncrement() % JUNK_LABELS == 0) {
                listOf(PUBLIC_ADDRESS)
            } else {
                throw UnknownHostException(host)
            }
        }

        assertEquals(ResolverTrust.UNTRUSTED, qualification.globalTrust())
    }

    @Test
    fun aTransientlyAmbiguousLaneCanStillPass() {
        val junkCalls = AtomicInteger()
        val qualification = qualification { host ->
            if (!host.endsWith(INVALID_SUFFIX)) {
                listOf(PUBLIC_ADDRESS)
            } else if (junkCalls.getAndIncrement() == 0) {
                listOf(PUBLIC_ADDRESS)
            } else {
                throw UnknownHostException(host)
            }
        }

        assertEquals(ResolverTrust.TRUSTED, qualification.globalTrust())
    }

    @Test
    fun oneLaneFailureDoesNotDiscardTheOtherLaneResult() {
        val junkCalls = AtomicInteger()
        val neverReleased = CountDownLatch(1)
        val start = System.nanoTime()
        val qualification = ResolverQualification(
            resolve = { host ->
                if (host.endsWith(INVALID_SUFFIX)) {
                    if (junkCalls.getAndIncrement() == 0) neverReleased.await(30, TimeUnit.SECONDS)
                    throw UnknownHostException(host)
                }
                listOf(PUBLIC_ADDRESS)
            },
            executor = pool(),
            junkLabelCount = JUNK_LABELS,
            canaries = CANARIES,
            // Virtual time runs 40x real, so a round budget of any size expires in milliseconds
            // while the probe that never answers is still blocked.
            clock = { (System.nanoTime() - start) / 25_000 }
        )

        assertEquals(ResolverTrust.TRUSTED, runBlocking { qualification.awaitGlobalTrust(200_000) })
    }

    @Test
    fun probesRunConcurrently() {
        val probeCount = JUNK_LABELS + CANARIES.size
        val allProbes = CountDownLatch(probeCount)
        val qualification = ResolverQualification(
            resolve = { host ->
                allProbes.countDown()
                allProbes.await(2, TimeUnit.SECONDS)
                if (host.endsWith(INVALID_SUFFIX)) throw UnknownHostException(host) else listOf(PUBLIC_ADDRESS)
            },
            executor = pool(),
            junkLabelCount = JUNK_LABELS,
            canaries = CANARIES,
            clock = System::currentTimeMillis
        )

        assertTrue(allProbes.await(5, TimeUnit.SECONDS))
        qualification.shutdown()
    }

    @Test
    fun aHostResolvingToPrivateSpaceIsUntrusted() {
        val qualification = qualification { host ->
            when {
                host == "api.example.com" -> listOf("192.168.1.1")
                host.endsWith(INVALID_SUFFIX) -> throw UnknownHostException(host)
                else -> listOf(PUBLIC_ADDRESS)
            }
        }

        assertEquals(ResolverTrust.UNTRUSTED, qualification.settledHostTrust("api.example.com"))
        assertEquals(ResolverTrust.TRUSTED, qualification.globalTrust())
    }

    @Test
    fun hostVerdictsAreBoundedAndEvictEldest() {
        val qualification = qualification(resolve = CLEAN_RESOLVE)
        repeat(HOST_CAP) { qualification.settledHostTrust("h$it.example.com") }

        qualification.hostTrust("h0.example.com")
        qualification.settledHostTrust("h$HOST_CAP.example.com")

        assertEquals(ResolverTrust.NONE, qualification.hostTrust("h1.example.com"))
        assertEquals(ResolverTrust.TRUSTED, qualification.hostTrust("h0.example.com"))
    }

    @Test
    fun aNetworkChangeFlushesEveryVerdict() {
        val qualification = qualification(resolve = CLEAN_RESOLVE)
        assertEquals(ResolverTrust.TRUSTED, qualification.globalTrust())
        assertEquals(ResolverTrust.TRUSTED, qualification.settledHostTrust("api.example.com"))

        qualification.onNetworkChanged()

        assertEquals(ResolverTrust.NONE, qualification.globalTrust())
        assertEquals(ResolverTrust.NONE, qualification.hostTrust("api.example.com"))
    }

    @Test
    fun readingNoneSchedulesARun() {
        val qualification = qualification(resolve = CLEAN_RESOLVE)
        qualification.onNetworkChanged()

        assertEquals(ResolverTrust.NONE, qualification.globalTrust())
        assertEquals(ResolverTrust.TRUSTED, qualification.globalTrust())
    }

    @Test
    fun shutdownSettlesAVerdictThatIsNeverComing() {
        val ticks = AtomicLong()
        val qualification = ResolverQualification(
            resolve = CLEAN_RESOLVE,
            executor = Executor { },
            junkLabelCount = JUNK_LABELS,
            canaries = CANARIES,
            // One tick per reading, so a wait that is not released by the shutdown reaches its
            // budget and answers NONE instead of hanging the suite.
            clock = { ticks.getAndIncrement() }
        )

        qualification.shutdown()

        assertEquals(ResolverTrust.UNTRUSTED, runBlocking { qualification.awaitGlobalTrust(1) })
        assertEquals(ResolverTrust.UNTRUSTED, runBlocking { qualification.awaitHostTrust("api.example.com", 1) })
    }

    @Test
    fun aVerdictFromASupersededRoundIsDiscarded() {
        val flushOnNextProbe = AtomicBoolean(false)
        lateinit var qualification: ResolverQualification
        qualification = qualification { host ->
            if (flushOnNextProbe.compareAndSet(true, false)) qualification.onNetworkChanged()
            CLEAN_RESOLVE(host)
        }
        assertEquals(ResolverTrust.TRUSTED, qualification.globalTrust())

        qualification.onNetworkChanged()
        flushOnNextProbe.set(true)
        qualification.globalTrust()

        assertEquals(ResolverTrust.NONE, qualification.globalTrust())
    }

    /** The verdict a host reaches once the run its first sight scheduled has finished. */
    private fun ResolverQualification.settledHostTrust(host: String): ResolverTrust {
        hostTrust(host)
        return hostTrust(host)
    }

    private fun pool(): ExecutorService = Executors.newCachedThreadPool().also { pools += it }

    /** Runs every probe on the calling thread, so a verdict is settled by the time a read returns. */
    private fun qualification(resolve: (String) -> List<String>) = ResolverQualification(
        resolve = resolve,
        executor = Executor { it.run() },
        junkLabelCount = JUNK_LABELS,
        canaries = CANARIES,
        clock = { 0L }
    )

    private companion object {
        const val PUBLIC_ADDRESS = "93.184.216.34"
        const val INVALID_SUFFIX = ".invalid"
        const val JUNK_LABELS = 3
        const val HOST_CAP = 64
        val CANARIES = listOf("google.com", "cloudflare.com", "wikipedia.org")
        val CLEAN_RESOLVE: (String) -> List<String> = { host ->
            if (host.endsWith(INVALID_SUFFIX)) throw UnknownHostException(host) else listOf(PUBLIC_ADDRESS)
        }
    }
}
