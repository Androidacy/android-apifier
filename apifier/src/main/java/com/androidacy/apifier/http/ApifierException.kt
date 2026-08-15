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

import java.io.IOException
import org.chromium.net.CronetException
import org.chromium.net.NetworkException

/** Cause of a failed call, apifier-owned codes alongside the codes Cronet itself reports. */
enum class ErrorCode {
    HOSTNAME_NOT_RESOLVED,
    INTERNET_DISCONNECTED,
    NETWORK_CHANGED,
    TIMED_OUT,
    CONNECTION_CLOSED,
    CONNECTION_TIMED_OUT,
    CONNECTION_REFUSED,
    CONNECTION_RESET,
    ADDRESS_UNREACHABLE,
    QUIC_PROTOCOL_FAILED,
    OTHER,
    CIRCUIT_OPEN,
    CANCELLED,
    CALL_TIMEOUT,
    DNS_UNTRUSTED,
    REDIRECT_REFUSED
}

/**
 * Root of apifier's transport failure hierarchy. Replaces the flattened
 * `IOException("Cronet request failed")` so a locally tripped circuit breaker or timeout
 * is distinguishable from an actual Cronet network failure.
 */
sealed class ApifierException(message: String, cause: Throwable? = null) : IOException(message, cause) {
    abstract val errorCode: ErrorCode
    open val retryable: Boolean = false

    /** A real Cronet network failure. Always retryable; [immediatelyRetryable] narrows the backoff. */
    class Transport(
        override val errorCode: ErrorCode,
        val cronetErrorCode: Int,
        val immediatelyRetryable: Boolean,
        message: String,
        cause: Throwable?
    ) : ApifierException(message, cause) {
        override val retryable: Boolean = true
    }

    /** The circuit breaker for [host] is open; the call never reached Cronet. */
    class CircuitOpen(val host: String) : ApifierException("Circuit open for host $host") {
        override val errorCode: ErrorCode = ErrorCode.CIRCUIT_OPEN
    }

    /** The call was cancelled by the caller. */
    class Cancelled : ApifierException("Call cancelled") {
        override val errorCode: ErrorCode = ErrorCode.CANCELLED
    }

    /** The call exceeded its apifier-enforced timeout of [timeoutMillis] ms. */
    class CallTimeout(val timeoutMillis: Long) : ApifierException("Call timed out after $timeoutMillis ms") {
        override val errorCode: ErrorCode = ErrorCode.CALL_TIMEOUT
    }

    /**
     * The transport declined to follow a redirect, because the chain grew past its limit or the
     * new location was not https. Terminal: a retry replays a request that was already refused.
     */
    class RedirectRefused(val reason: String) : ApifierException(reason) {
        override val errorCode: ErrorCode = ErrorCode.REDIRECT_REFUSED
    }

    /** The protected-domain check found [host]'s system DNS answer untrusted or unverifiable. */
    class DnsUntrusted(val host: String) : ApifierException("DNS answer for host $host is untrusted") {
        override val errorCode: ErrorCode = ErrorCode.DNS_UNTRUSTED
    }

    /**
     * A failure the pipeline does not model, carried in [cause]. Consumers are promised this
     * hierarchy for every failure, and a raw throwable would otherwise reach them as something a
     * `catch (IOException)` or an `is ApifierException` check misses.
     */
    class Unexpected(cause: Throwable) : ApifierException(cause.toString(), cause) {
        override val errorCode: ErrorCode = ErrorCode.OTHER
    }

    /** The response carried a non-2xx status of [code]. Thrown by [successOrThrow]. */
    class HttpError(val code: Int) : ApifierException("HTTP request failed with status $code") {
        override val errorCode: ErrorCode = ErrorCode.OTHER
    }
}

private fun mapNetworkErrorCode(code: Int): ErrorCode = when (code) {
    NetworkException.ERROR_HOSTNAME_NOT_RESOLVED -> ErrorCode.HOSTNAME_NOT_RESOLVED
    NetworkException.ERROR_INTERNET_DISCONNECTED -> ErrorCode.INTERNET_DISCONNECTED
    NetworkException.ERROR_NETWORK_CHANGED -> ErrorCode.NETWORK_CHANGED
    NetworkException.ERROR_TIMED_OUT -> ErrorCode.TIMED_OUT
    NetworkException.ERROR_CONNECTION_CLOSED -> ErrorCode.CONNECTION_CLOSED
    NetworkException.ERROR_CONNECTION_TIMED_OUT -> ErrorCode.CONNECTION_TIMED_OUT
    NetworkException.ERROR_CONNECTION_REFUSED -> ErrorCode.CONNECTION_REFUSED
    NetworkException.ERROR_CONNECTION_RESET -> ErrorCode.CONNECTION_RESET
    NetworkException.ERROR_ADDRESS_UNREACHABLE -> ErrorCode.ADDRESS_UNREACHABLE
    NetworkException.ERROR_QUIC_PROTOCOL_FAILED -> ErrorCode.QUIC_PROTOCOL_FAILED
    else -> ErrorCode.OTHER
}

/**
 * Converts a Cronet failure into [ApifierException.Transport]. A [NetworkException] maps its
 * `getErrorCode()` across all 11 `ERROR_*` constants; anything else, or an unrecognized code,
 * becomes [ErrorCode.OTHER] with `cronetErrorCode` carrying `getCronetInternalErrorCode()`
 * when the exception exposes one and 0 otherwise.
 */
fun CronetException.toApifierException(): ApifierException.Transport {
    val networkException = this as? NetworkException
    val errorCode = networkException?.let { mapNetworkErrorCode(it.errorCode) } ?: ErrorCode.OTHER
    val cronetErrorCode = networkException?.cronetInternalErrorCode ?: 0
    val immediatelyRetryable = networkException?.immediatelyRetryable() ?: false
    return ApifierException.Transport(
        errorCode = errorCode,
        cronetErrorCode = cronetErrorCode,
        immediatelyRetryable = immediatelyRetryable,
        message = message ?: "Cronet request failed",
        cause = this
    )
}
