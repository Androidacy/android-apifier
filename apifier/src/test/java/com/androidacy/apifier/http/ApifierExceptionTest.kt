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

import org.chromium.net.CronetException
import org.chromium.net.NetworkException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

private class FakeNetworkException(
    private val code: Int,
    private val internalCode: Int = 0,
    private val immediate: Boolean = false
) : NetworkException("fake network exception", RuntimeException("fake underlying cause")) {
    override fun getErrorCode(): Int = code
    override fun getCronetInternalErrorCode(): Int = internalCode
    override fun immediatelyRetryable(): Boolean = immediate
}

private class FakeCronetException(cause: Throwable) : CronetException("fake cronet exception", cause)

class ApifierExceptionTest {

    @Test
    fun mapsEveryNetworkExceptionCode() {
        val expected = mapOf(
            NetworkException.ERROR_HOSTNAME_NOT_RESOLVED to ErrorCode.HOSTNAME_NOT_RESOLVED,
            NetworkException.ERROR_INTERNET_DISCONNECTED to ErrorCode.INTERNET_DISCONNECTED,
            NetworkException.ERROR_NETWORK_CHANGED to ErrorCode.NETWORK_CHANGED,
            NetworkException.ERROR_TIMED_OUT to ErrorCode.TIMED_OUT,
            NetworkException.ERROR_CONNECTION_CLOSED to ErrorCode.CONNECTION_CLOSED,
            NetworkException.ERROR_CONNECTION_TIMED_OUT to ErrorCode.CONNECTION_TIMED_OUT,
            NetworkException.ERROR_CONNECTION_REFUSED to ErrorCode.CONNECTION_REFUSED,
            NetworkException.ERROR_CONNECTION_RESET to ErrorCode.CONNECTION_RESET,
            NetworkException.ERROR_ADDRESS_UNREACHABLE to ErrorCode.ADDRESS_UNREACHABLE,
            NetworkException.ERROR_QUIC_PROTOCOL_FAILED to ErrorCode.QUIC_PROTOCOL_FAILED,
            NetworkException.ERROR_OTHER to ErrorCode.OTHER
        )

        expected.forEach { (cronetCode, apifierCode) ->
            val mapped = FakeNetworkException(cronetCode).toApifierException()
            assertEquals("code $cronetCode", apifierCode, mapped.errorCode)
        }
    }

    @Test
    fun unknownCodeMapsToOther() {
        val mapped = FakeNetworkException(code = 999, internalCode = 42).toApifierException()

        assertEquals(ErrorCode.OTHER, mapped.errorCode)
        assertEquals(42, mapped.cronetErrorCode)
    }

    @Test
    fun nonNetworkCronetExceptionMapsToOther() {
        val cause = RuntimeException("boom")
        val cronetException = FakeCronetException(cause)

        val mapped = cronetException.toApifierException()

        assertEquals(ErrorCode.OTHER, mapped.errorCode)
        assertEquals(0, mapped.cronetErrorCode)
        assertSame(cronetException, mapped.cause)
    }

    @Test
    fun apifierOwnedCodesAreNotRetryable() {
        assertFalse(ApifierException.CircuitOpen("example.com").retryable)
        assertFalse(ApifierException.Cancelled().retryable)
        assertFalse(ApifierException.CallTimeout(5_000).retryable)
        assertFalse(ApifierException.DnsUntrusted("example.com").retryable)

        val refused = ApifierException.RedirectRefused("Redirect to non-HTTPS URL rejected")
        assertFalse(refused.retryable)
        assertEquals(ErrorCode.REDIRECT_REFUSED, refused.errorCode)
    }

    @Test
    fun transportIsRetryableAndKeepsImmediateFlag() {
        val retryableTransport = FakeNetworkException(
            code = NetworkException.ERROR_CONNECTION_RESET,
            immediate = true
        ).toApifierException()
        assertTrue(retryableTransport.retryable)
        assertTrue(retryableTransport.immediatelyRetryable)

        val deferredTransport = FakeNetworkException(
            code = NetworkException.ERROR_CONNECTION_RESET,
            immediate = false
        ).toApifierException()
        assertTrue(deferredTransport.retryable)
        assertFalse(deferredTransport.immediatelyRetryable)
    }
}
