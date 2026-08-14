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

import android.content.Context
import com.androidacy.apifier.patterns.BackoffConfig
import com.androidacy.apifier.patterns.ExponentialBackoff
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.Condition
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Trust verdict for one protected host. */
enum class TrustStatus { UNKNOWN, OK, FAIL, ERROR }

/**
 * Compares what the system resolver answers for each protected domain against known-good public
 * resolvers, and reports whether the answers agree.
 *
 * Verdicts are computed on [executor] and read back through [status]; no log line carries any
 * part of the contract, since release builds strip logging.
 */
class ProtectedDomainCheck internal constructor(
    protectedDomains: List<String>,
    private val resolvers: List<TrustedResolver>,
    private val systemResolve: (String) -> List<String>,
    private val executor: Executor,
    private val clock: () -> Long = System::currentTimeMillis
) {

    private val domains: Set<String> = protectedDomains.map { domain ->
        require(AddressClassifier.isSafeHostname(domain)) { "Unsafe protected domain: \"$domain\"" }
        domain.lowercase()
    }.toSet()

    private val states = domains.associateWith { HostState() }
    private val backoff = ExponentialBackoff(
        BackoffConfig(maxAttempts = Int.MAX_VALUE, baseDelayMs = 5_000, maxDelayMs = 300_000)
    )

    private val generation = AtomicInteger(0)

    @Volatile private var enforce = true
    @Volatile private var stopped = false

    /** True while a `FAIL` or repeated `ERROR` verdict is allowed to block requests. */
    val enforcing: Boolean get() = enforce

    /** Begins background verdicts for every protected domain. */
    fun start() {
        domains.forEach { submit(it) }
    }

    /** Stops scheduling further verdicts and releases anything waiting in [awaitVerdict]. */
    fun shutdown() {
        stopped = true
        states.values.forEach { state -> state.lock.withLock { state.updated.signalAll() } }
    }

    /** Latest verdict for [host], or `UNKNOWN` when it is not protected or has no verdict yet. */
    fun status(host: String): TrustStatus {
        val state = stateOf(host) ?: return TrustStatus.UNKNOWN
        scheduleIfDue(host.lowercase(), state)
        return state.status
    }

    /** Waits up to [deadlineMs] for a verdict on [host], returning `UNKNOWN` if none arrives. */
    fun awaitVerdict(host: String, deadlineMs: Long): TrustStatus {
        val key = host.lowercase()
        val state = states[key] ?: return TrustStatus.UNKNOWN
        scheduleIfDue(key, state)
        state.lock.withLock {
            var remaining = TimeUnit.MILLISECONDS.toNanos(deadlineMs)
            while (state.status == TrustStatus.UNKNOWN && !stopped && remaining > 0) {
                remaining = state.updated.awaitNanos(remaining)
            }
        }
        return state.status
    }

    /** Drops every verdict and recomputes, since a new network invalidates what the old one proved. */
    fun onNetworkChanged() {
        generation.incrementAndGet()
        states.forEach { (host, state) ->
            state.lock.withLock {
                state.status = TrustStatus.UNKNOWN
                state.consecutiveErrors = 0
                state.attempt = 0
                state.nextAttemptAtMillis = 0
            }
            submit(host)
        }
    }

    /** Turns blocking on or off. Verdicts keep computing either way and stay readable via [status]. */
    fun setEnforceProtectedDomains(enforce: Boolean) {
        this.enforce = enforce
    }

    /**
     * Whether a request to [host] must be refused. `UNKNOWN` never blocks, and a single `ERROR`
     * never blocks either, so one unlucky network moment cannot take the app offline.
     */
    fun shouldBlock(host: String): Boolean {
        if (!enforce) return false
        val key = host.lowercase()
        val state = states[key] ?: return false
        scheduleIfDue(key, state)
        return when (state.status) {
            TrustStatus.FAIL -> true
            TrustStatus.ERROR -> state.consecutiveErrors >= ERROR_BLOCK_THRESHOLD
            TrustStatus.OK, TrustStatus.UNKNOWN -> false
        }
    }

    private fun stateOf(host: String): HostState? = states[host.lowercase()]

    /**
     * `ERROR` and `FAIL` re-evaluate on the backoff schedule; `OK` stands until the network
     * changes. Re-evaluation is triggered by whoever reads the status rather than by a timer,
     * so this class owns no thread beyond the executor it was handed.
     */
    private fun scheduleIfDue(host: String, state: HostState) {
        if (stopped || state.status == TrustStatus.UNKNOWN || state.status == TrustStatus.OK) return
        if (clock() < state.nextAttemptAtMillis) return
        submit(host)
    }

    private fun submit(host: String) {
        val state = states[host] ?: return
        if (stopped || !state.running.compareAndSet(false, true)) return
        val submittedAt = generation.get()
        executor.execute {
            val verdict = try {
                evaluate(host)
            } catch (e: Throwable) {
                // Without this the executor swallows it and the host stays UNKNOWN for the
                // life of the process.
                TrustStatus.ERROR
            } finally {
                state.running.set(false)
            }
            // A verdict from before a network change describes queries issued on the old network.
            // Publishing it would overwrite the reset with a stale answer, and a stale OK stands
            // until the next network change because nothing reschedules an OK.
            if (submittedAt == generation.get()) publish(state, verdict) else submit(host)
        }
    }

    private fun publish(state: HostState, verdict: TrustStatus) {
        state.lock.withLock {
            state.status = verdict
            state.consecutiveErrors =
                if (verdict == TrustStatus.ERROR) state.consecutiveErrors + 1 else 0
            if (verdict == TrustStatus.OK) {
                state.attempt = 0
                state.nextAttemptAtMillis = 0
            } else {
                state.nextAttemptAtMillis = clock() + backoff.calculateDelay(state.attempt)
                state.attempt++
            }
            state.updated.signalAll()
        }
    }

    private fun evaluate(host: String): TrustStatus {
        val answers = mutableListOf<DnsAnswer>()
        var certificateRejected = false
        var primaryFailed = false

        for ((index, resolver) in resolvers.withIndex()) {
            val isBackup = index >= PRIMARY_RESOLVERS
            if (isBackup && !primaryFailed) break
            if (!resolver.isAvailable()) {
                if (!isBackup) primaryFailed = true
                continue
            }
            try {
                answers.add(resolver.query(host))
            } catch (e: CertificateRejectedException) {
                certificateRejected = true
                if (!isBackup) primaryFailed = true
            } catch (e: IOException) {
                if (!isBackup) primaryFailed = true
            }
        }

        // Decides alone, ahead of the answer comparison: these connections are dialed to an IP
        // literal against a pinned root, so a rejected certificate is interception.
        if (certificateRejected) return TrustStatus.FAIL
        if (answers.size < MIN_USABLE_ANSWERS) return TrustStatus.ERROR

        val systemAddresses = try {
            systemResolve(host)
        } catch (e: IOException) {
            return TrustStatus.ERROR
        }
        // Nothing resolved means there was nothing to connect to, so the comparison never
        // happened; that is a failure to check, not evidence of interception.
        if (systemAddresses.isEmpty()) return TrustStatus.ERROR

        if (systemAddresses.any { AddressClassifier.classify(it) != AddressCategory.PUBLIC }) {
            return TrustStatus.FAIL
        }

        val trusted = answers.flatMap { it.addresses }.mapNotNull(::canonical).toSet()
        val system = systemAddresses.mapNotNull(::canonical).toSet()
        return if (system.any { it in trusted }) TrustStatus.OK else TrustStatus.FAIL
    }

    /** Byte form, so `2606:4700::1111` and its expanded spelling compare equal. */
    private fun canonical(ip: String): String? {
        if (!AddressClassifier.isIpLiteral(ip)) return null
        return runCatching {
            InetAddress.getByName(ip.removeSurrounding("[", "]")).address.joinToString("") {
                "%02x".format(it)
            }
        }.getOrNull()
    }

    private class HostState {
        val lock = ReentrantLock()
        val updated: Condition = lock.newCondition()
        val running = AtomicBoolean(false)
        @Volatile var status: TrustStatus = TrustStatus.UNKNOWN
        @Volatile var consecutiveErrors: Int = 0
        @Volatile var attempt: Int = 0
        @Volatile var nextAttemptAtMillis: Long = 0
    }

    companion object {
        private const val PRIMARY_RESOLVERS = 2
        private const val MIN_USABLE_ANSWERS = 2
        private const val ERROR_BLOCK_THRESHOLD = 2

        /**
         * Builds the check over cloudflare, google, and the AdGuard unfiltered endpoint in that
         * role order. AdGuard's default endpoint sinkholes filtered domains, so it would answer
         * with policy rather than with what the zone says and could not serve as a comparison.
         */
        fun production(
            context: Context,
            domains: List<String>,
            executor: Executor
        ): ProtectedDomainCheck {
            val trust = PinnedRootTrust.load(context)
            val resolvers = listOf(
                TrustedResolver("cloudflare", "https://1.1.1.1/dns-query", trust),
                TrustedResolver("google", "https://8.8.8.8/dns-query", trust),
                TrustedResolver("adguard-unfiltered", "https://94.140.14.140/dns-query", trust)
            )
            return ProtectedDomainCheck(
                domains,
                resolvers,
                { host -> InetAddress.getAllByName(host).mapNotNull { it.hostAddress } },
                executor
            )
        }
    }
}
