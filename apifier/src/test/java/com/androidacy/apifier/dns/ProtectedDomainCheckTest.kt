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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.UnknownHostException
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.concurrent.Executor

class ProtectedDomainCheckTest {

    private val executor = QueuedExecutor()
    private var now = 1_000L
    private lateinit var trust: PinnedRootTrust

    @Before
    fun setUp() {
        val ca = KeyStore.getInstance("PKCS12")
        checkNotNull(javaClass.classLoader?.getResourceAsStream("dns/test_ca.p12"))
            .use { ca.load(it, "apifier-test".toCharArray()) }
        trust = PinnedRootTrust(listOf(ca.getCertificate("ca") as X509Certificate))
    }

    @Test
    fun verdictOkOnPartialOverlap() {
        val check = checkOver(
            listOf(answering("8.8.8.8"), answering("8.8.8.8", "9.9.9.9"), answering("9.9.9.9")),
            system = listOf("1.1.1.1", "8.8.8.8")
        )

        check.start()
        executor.runAll()

        assertEquals(TrustStatus.OK, check.status(HOST))
    }

    @Test
    fun verdictFailOnZeroOverlap() {
        val check = checkOver(
            listOf(answering("8.8.8.8"), answering("9.9.9.9"), answering("9.9.9.9")),
            system = listOf("1.1.1.1")
        )

        check.start()
        executor.runAll()

        assertEquals(TrustStatus.FAIL, check.status(HOST))
    }

    @Test
    fun verdictFailOnNonRoutableSystemAnswer() {
        val check = checkOver(
            listOf(answering("1.1.1.1"), answering("1.1.1.1"), answering("1.1.1.1")),
            system = listOf("192.168.1.1", "1.1.1.1")
        )

        check.start()
        executor.runAll()

        assertEquals(TrustStatus.FAIL, check.status(HOST))
    }

    @Test
    fun verdictErrorOnSingleUsableResponse() {
        val check = checkOver(
            listOf(answering("1.1.1.1"), unreachable(), unreachable()),
            system = listOf("1.1.1.1")
        )

        check.start()
        executor.runAll()

        assertEquals(TrustStatus.ERROR, check.status(HOST))
    }

    @Test
    fun verdictErrorWhenSystemResolveFails() {
        val check = ProtectedDomainCheck(
            listOf(HOST),
            listOf(answering("1.1.1.1"), answering("1.1.1.1"), answering("1.1.1.1")),
            { throw UnknownHostException(it) },
            executor,
            { now }
        )

        check.start()
        executor.runAll()

        assertEquals(TrustStatus.ERROR, check.status(HOST))
    }

    @Test
    fun backupConsultedOnlyOnPrimaryFailure() {
        val quietBackup = answering("1.1.1.1")
        val healthy = checkOver(
            listOf(answering("1.1.1.1"), answering("1.1.1.1"), quietBackup),
            system = listOf("1.1.1.1")
        )
        healthy.start()
        executor.runAll()
        assertEquals(0, quietBackup.queryCount)

        val consultedBackup = answering("1.1.1.1")
        val degraded = checkOver(
            listOf(unreachable(), answering("1.1.1.1"), consultedBackup),
            system = listOf("1.1.1.1")
        )
        degraded.start()
        executor.runAll()
        assertEquals(1, consultedBackup.queryCount)
    }

    @Test
    fun backupConsultedWhenPrimaryIsInBackoff() {
        val backup = answering("1.1.1.1")
        val sidelined = answering("1.1.1.1").apply { available = false }
        val check = checkOver(
            listOf(sidelined, answering("1.1.1.1"), backup),
            system = listOf("1.1.1.1")
        )

        check.start()
        executor.runAll()

        assertEquals(0, sidelined.queryCount)
        assertEquals(1, backup.queryCount)
        assertEquals(TrustStatus.OK, check.status(HOST))
    }

    @Test
    fun verdictFailOnRejectedCertificate() {
        val check = checkOver(
            listOf(rejectingCertificate(), answering("1.1.1.1"), answering("1.1.1.1")),
            system = listOf("1.1.1.1")
        )

        check.start()
        executor.runAll()

        assertEquals(TrustStatus.FAIL, check.status(HOST))
    }

    @Test
    fun connectionFailureIsNotFail() {
        val check = checkOver(
            listOf(unreachable(), answering("1.1.1.1"), answering("1.1.1.1")),
            system = listOf("1.1.1.1")
        )

        check.start()
        executor.runAll()

        assertEquals(TrustStatus.OK, check.status(HOST))
    }

    @Test
    fun emptyTrustedAnswerIsUsable() {
        val check = checkOver(
            listOf(answeringNothing(), answeringNothing(), answeringNothing()),
            system = listOf("1.1.1.1")
        )

        check.start()
        executor.runAll()

        assertEquals(TrustStatus.FAIL, check.status(HOST))
    }

    @Test
    fun rejectedCertificateOutranksErrorThreshold() {
        val check = checkOver(
            listOf(rejectingCertificate(), unreachable(), answering("1.1.1.1")),
            system = listOf("1.1.1.1")
        )

        check.start()
        executor.runAll()

        assertEquals(TrustStatus.FAIL, check.status(HOST))
    }

    @Test
    fun firstErrorDoesNotBlock() {
        val check = checkOver(listOf(unreachable(), unreachable(), unreachable()), listOf("1.1.1.1"))

        check.start()
        executor.runAll()

        assertEquals(TrustStatus.ERROR, check.status(HOST))
        assertFalse(check.shouldBlock(HOST))
    }

    @Test
    fun secondConsecutiveErrorBlocks() {
        val check = checkOver(listOf(unreachable(), unreachable(), unreachable()), listOf("1.1.1.1"))
        check.start()
        executor.runAll()

        now += 600_000
        check.shouldBlock(HOST)
        executor.runAll()

        assertEquals(TrustStatus.ERROR, check.status(HOST))
        assertTrue(check.shouldBlock(HOST))
    }

    @Test
    fun failBlocksOnlyWhenEnforcing() {
        val check = checkOver(
            listOf(answering("8.8.8.8"), answering("8.8.8.8"), answering("8.8.8.8")),
            system = listOf("1.1.1.1")
        )
        check.start()
        executor.runAll()
        assertTrue(check.shouldBlock(HOST))

        check.setEnforceProtectedDomains(false)

        assertFalse(check.enforcing)
        assertFalse(check.shouldBlock(HOST))
        assertEquals(TrustStatus.FAIL, check.status(HOST))
    }

    @Test
    fun unknownReleasesAtDeadline() {
        val check = checkOver(
            listOf(answering("1.1.1.1"), answering("1.1.1.1"), answering("1.1.1.1")),
            system = listOf("1.1.1.1")
        )
        check.start()

        val started = System.nanoTime()
        val verdict = check.awaitVerdict(HOST, 60)
        val elapsedMs = (System.nanoTime() - started) / 1_000_000

        assertEquals(TrustStatus.UNKNOWN, verdict)
        assertTrue("returned after ${elapsedMs}ms", elapsedMs >= 50)
        assertFalse(check.shouldBlock(HOST))
    }

    @Test
    fun networkChangeResetsToUnknown() {
        val resolver = answering("1.1.1.1")
        val check = checkOver(
            listOf(resolver, answering("1.1.1.1"), answering("1.1.1.1")),
            system = listOf("1.1.1.1")
        )
        check.start()
        executor.runAll()
        assertEquals(TrustStatus.OK, check.status(HOST))

        check.onNetworkChanged()
        assertEquals(TrustStatus.UNKNOWN, check.status(HOST))

        executor.runAll()
        assertEquals(TrustStatus.OK, check.status(HOST))
        assertEquals(2, resolver.queryCount)
    }

    @Test
    fun unrelatedHostNeverGated() {
        val check = checkOver(
            listOf(answering("8.8.8.8"), answering("8.8.8.8"), answering("8.8.8.8")),
            system = listOf("1.1.1.1")
        )
        check.start()
        executor.runAll()

        assertFalse(check.shouldBlock("unrelated.example"))
        assertEquals(TrustStatus.UNKNOWN, check.status("unrelated.example"))
    }

    @Test
    fun unsafeProtectedDomainRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            ProtectedDomainCheck(
                listOf("evil host!"),
                listOf(answering("1.1.1.1")),
                { listOf("1.1.1.1") },
                executor,
                { now }
            )
        }
    }

    private fun checkOver(resolvers: List<TrustedResolver>, system: List<String>) =
        ProtectedDomainCheck(listOf(HOST), resolvers, { system }, executor, { now })

    private fun answering(vararg addresses: String) =
        FakeResolver(trust) { DnsAnswer(addresses.toList(), 60) }

    private fun answeringNothing() = FakeResolver(trust) { DnsAnswer(emptyList(), 0) }

    private fun unreachable() =
        FakeResolver(trust) { throw ResolverUnavailableException("refused", null) }

    private fun rejectingCertificate() =
        FakeResolver(trust) { throw CertificateRejectedException("pinned validation failed", null) }

    private class FakeResolver(
        trust: PinnedRootTrust,
        private val outcome: () -> DnsAnswer
    ) : TrustedResolver("fake", "https://127.0.0.1/dns-query", trust) {

        var queryCount = 0
            private set
        var available = true

        override fun isAvailable(): Boolean = available

        override fun query(hostname: String): DnsAnswer {
            queryCount++
            return outcome()
        }
    }

    private class QueuedExecutor : Executor {
        private val tasks = ArrayDeque<Runnable>()

        override fun execute(command: Runnable) {
            tasks.addLast(command)
        }

        fun runAll() {
            while (tasks.isNotEmpty()) tasks.removeFirst().run()
        }
    }

    private companion object {
        const val HOST = "api.example.com"
    }
}
