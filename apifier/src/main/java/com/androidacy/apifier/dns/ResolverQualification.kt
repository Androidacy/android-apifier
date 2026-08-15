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

import java.net.InetAddress
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicReferenceArray
import kotlinx.coroutines.delay

/** How far the platform resolver has been shown to answer honestly. */
internal enum class ResolverTrust {

    /** No verdict yet. Transient, and never a reason to refuse anything. */
    NONE,
    TRUSTED,
    UNTRUSTED
}

/**
 * Qualifies the resolver the platform hands the app, without reference to any host the app is
 * about to contact.
 *
 * Two global lanes run together: names under `.invalid` that must not resolve, and public canary
 * names that must resolve to public space. A lane where every probe agrees is a verdict; a lane
 * whose probes disagree is retried once, and disagreement twice is [ResolverTrust.UNTRUSTED],
 * because a resolver that cannot produce a consistent picture twice is itself the signal.
 *
 * The per-host check survives geo-DNS fronting: a sinkholed answer reaches every resolution path,
 * while a geo-steered one does not.
 */
internal class ResolverQualification(
    private val resolve: (String) -> List<String>,
    private val executor: Executor,
    private val junkLabelCount: Int,
    private val canaries: List<String>,
    private val clock: () -> Long
) {

    private enum class ProbeKind { JUNK, PUBLIC_NAME }

    private enum class ProbeResult { CLEAN, REWRITTEN, UNKNOWN }

    private enum class LaneResult { PASS, FAIL, AMBIGUOUS }

    private class Probe(val host: String, val kind: ProbeKind)

    private val random = SecureRandom()
    private val globalVerdict = AtomicReference(ResolverTrust.NONE)
    private val globalRunning = AtomicBoolean(false)
    private val hostsRunning = ConcurrentHashMap.newKeySet<String>()
    private val generation = AtomicLong()
    private val closed = AtomicBoolean(false)

    private val hostVerdicts = object : LinkedHashMap<String, ResolverTrust>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, ResolverTrust>): Boolean =
            size > MAX_HOSTS
    }

    init {
        scheduleGlobal()
    }

    /** The global verdict, scheduling a run when there is none yet. */
    fun globalTrust(): ResolverTrust {
        val verdict = globalVerdict.get()
        if (verdict == ResolverTrust.NONE) scheduleGlobal()
        return verdict
    }

    /**
     * The global verdict once it settles, or [ResolverTrust.NONE] if [budgetMs] elapses first.
     * The budget is measured with the injected clock, which has to advance for it to expire.
     */
    suspend fun awaitGlobalTrust(budgetMs: Long): ResolverTrust {
        val deadline = clock() + budgetMs
        while (true) {
            val verdict = globalTrust()
            if (verdict != ResolverTrust.NONE) return verdict
            if (clock() >= deadline) return ResolverTrust.NONE
            delay(POLL_INTERVAL_MS)
        }
    }

    /** The verdict for [host], scheduling a run on first sight and on every sight after a flush. */
    fun hostTrust(host: String): ResolverTrust {
        val verdict = synchronized(hostVerdicts) { hostVerdicts[host] }
        if (verdict != null) return verdict
        scheduleHost(host)
        return ResolverTrust.NONE
    }

    /**
     * The verdict for [host] once it settles, or [ResolverTrust.NONE] if [budgetMs] elapses first.
     * The budget is measured with the injected clock, which has to advance for it to expire.
     */
    suspend fun awaitHostTrust(host: String, budgetMs: Long): ResolverTrust {
        val deadline = clock() + budgetMs
        while (true) {
            val verdict = hostTrust(host)
            if (verdict != ResolverTrust.NONE) return verdict
            if (clock() >= deadline) return ResolverTrust.NONE
            delay(POLL_INTERVAL_MS)
        }
    }

    /** Discards every verdict, since a new network invalidates what the old one proved. */
    fun onNetworkChanged() {
        generation.incrementAndGet()
        globalVerdict.set(ResolverTrust.NONE)
        synchronized(hostVerdicts) { hostVerdicts.clear() }
    }

    /** Stops scheduling further runs. The supplied executor belongs to the caller and is left alone. */
    fun shutdown() {
        closed.set(true)
    }

    private fun scheduleGlobal() {
        if (closed.get() || !globalRunning.compareAndSet(false, true)) return
        val scheduledAt = generation.get()
        try {
            executor.execute {
                try {
                    val verdict = qualifyGlobal()
                    if (scheduledAt == generation.get()) globalVerdict.set(verdict)
                } finally {
                    globalRunning.set(false)
                }
            }
        } catch (e: RejectedExecutionException) {
            globalRunning.set(false)
        }
    }

    private fun scheduleHost(host: String) {
        if (closed.get() || !hostsRunning.add(host)) return
        val scheduledAt = generation.get()
        try {
            executor.execute {
                try {
                    val verdict = qualifyHost(host)
                    synchronized(hostVerdicts) {
                        if (scheduledAt == generation.get()) hostVerdicts[host] = verdict
                    }
                } finally {
                    hostsRunning.remove(host)
                }
            }
        } catch (e: RejectedExecutionException) {
            hostsRunning.remove(host)
        }
    }

    private fun qualifyGlobal(): ResolverTrust {
        val first = runProbes(junkProbes() + canaryProbes())
        var junk = laneOf(first, ProbeKind.JUNK)
        var canary = laneOf(first, ProbeKind.PUBLIC_NAME)
        val ambiguous = junk == LaneResult.AMBIGUOUS || canary == LaneResult.AMBIGUOUS
        val failed = junk == LaneResult.FAIL || canary == LaneResult.FAIL
        if (ambiguous && !failed) {
            val second = runProbes(
                (if (junk == LaneResult.AMBIGUOUS) junkProbes() else emptyList()) +
                    (if (canary == LaneResult.AMBIGUOUS) canaryProbes() else emptyList())
            )
            if (junk == LaneResult.AMBIGUOUS) junk = laneOf(second, ProbeKind.JUNK)
            if (canary == LaneResult.AMBIGUOUS) canary = laneOf(second, ProbeKind.PUBLIC_NAME)
        }
        return if (junk == LaneResult.PASS && canary == LaneResult.PASS) {
            ResolverTrust.TRUSTED
        } else {
            ResolverTrust.UNTRUSTED
        }
    }

    private fun qualifyHost(host: String): ResolverTrust {
        val probe = listOf(Probe(host, ProbeKind.PUBLIC_NAME))
        var lane = laneOf(runProbes(probe), ProbeKind.PUBLIC_NAME)
        if (lane == LaneResult.AMBIGUOUS) lane = laneOf(runProbes(probe), ProbeKind.PUBLIC_NAME)
        return if (lane == LaneResult.PASS) ResolverTrust.TRUSTED else ResolverTrust.UNTRUSTED
    }

    /**
     * Runs every probe together and collects what has arrived by the round deadline. Probes are
     * never cancelled for each other: a junk label that hangs cannot discard a canary answer that
     * already arrived.
     */
    private fun runProbes(probes: List<Probe>): List<Pair<Probe, ProbeResult>> {
        val results = AtomicReferenceArray<ProbeResult>(probes.size)
        val done = CountDownLatch(probes.size)
        val deadline = clock() + ROUND_BUDGET_MS
        probes.forEachIndexed { index, probe ->
            try {
                executor.execute {
                    try {
                        results.set(index, outcomeOf(probe))
                    } finally {
                        done.countDown()
                    }
                }
            } catch (e: RejectedExecutionException) {
                done.countDown()
            }
        }
        try {
            while (done.count > 0L && clock() < deadline) {
                done.await(POLL_INTERVAL_MS, TimeUnit.MILLISECONDS)
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        return probes.mapIndexed { index, probe -> probe to (results.get(index) ?: silence(probe.kind)) }
    }

    private fun outcomeOf(probe: Probe): ProbeResult {
        val answers = try {
            resolve(probe.host)
        } catch (e: Exception) {
            // resolve is supplied by the caller; whatever it throws is the absence of an answer.
            return silence(probe.kind)
        }
        if (answers.isEmpty()) return silence(probe.kind)
        return when (probe.kind) {
            ProbeKind.JUNK -> ProbeResult.REWRITTEN
            ProbeKind.PUBLIC_NAME ->
                if (answers.all { AddressClassifier.classify(it) == AddressCategory.PUBLIC }) {
                    ProbeResult.CLEAN
                } else {
                    ProbeResult.REWRITTEN
                }
        }
    }

    /** Silence is the correct answer for a name that is never delegated, and no answer at all otherwise. */
    private fun silence(kind: ProbeKind): ProbeResult = when (kind) {
        ProbeKind.JUNK -> ProbeResult.CLEAN
        ProbeKind.PUBLIC_NAME -> ProbeResult.UNKNOWN
    }

    private fun laneOf(results: List<Pair<Probe, ProbeResult>>, kind: ProbeKind): LaneResult {
        val lane = results.filter { it.first.kind == kind }.map { it.second }
        return when {
            lane.all { it == ProbeResult.CLEAN } -> LaneResult.PASS
            lane.all { it == ProbeResult.REWRITTEN } -> LaneResult.FAIL
            else -> LaneResult.AMBIGUOUS
        }
    }

    /**
     * RFC 2606 keeps `.invalid` undelegated, so any answer under it is a resolver rewriting
     * NXDOMAIN. Labels are drawn fresh per round: a fixed list can be allowlisted by a hostile
     * resolver, random labels cannot.
     */
    private fun junkProbes(): List<Probe> = List(junkLabelCount) {
        val label = String(CharArray(LABEL_LENGTH) { LABEL_ALPHABET[random.nextInt(LABEL_ALPHABET.length)] })
        Probe("$label.invalid", ProbeKind.JUNK)
    }

    private fun canaryProbes(): List<Probe> = canaries.map { Probe(it, ProbeKind.PUBLIC_NAME) }

    internal companion object {

        private const val MAX_HOSTS = 64
        private const val ROUND_BUDGET_MS = 5_000L
        private const val POLL_INTERVAL_MS = 20L
        private const val JUNK_LABEL_COUNT = 3
        private const val LABEL_LENGTH = 12
        private const val LABEL_ALPHABET = "abcdefghijklmnopqrstuvwxyz"

        /** None of these is ours, so no consumer's refusal depends on our infrastructure staying up. */
        private val CANARIES = listOf("google.com", "cloudflare.com", "wikipedia.org")

        /**
         * The qualification a client runs. [executor] has to run tasks in parallel: a round waits
         * on the probes it submits, so a single-threaded executor would starve them.
         */
        fun production(executor: Executor): ResolverQualification = ResolverQualification(
            resolve = { host -> InetAddress.getAllByName(host).mapNotNull { it.hostAddress } },
            executor = executor,
            junkLabelCount = JUNK_LABEL_COUNT,
            canaries = CANARIES,
            clock = System::currentTimeMillis
        )
    }
}
