# Android Apifier

[![Release](https://img.shields.io/github/v/release/Androidacy/android-apifier?sort=semver)](https://github.com/Androidacy/android-apifier/releases/latest)
[![](https://jitpack.io/v/Androidacy/android-apifier.svg)](https://jitpack.io/#Androidacy/android-apifier)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

HTTP and API networking library for Android, built directly on Cronet.

## Features

- **Coroutine call surface**: `send()` and its shorthands (`get`, `post`, `delete`, `head`,
  `download`, `upload`) are `suspend` functions on `Requester`; the callback-based `Call`/`Callback`
  surface still works but is deprecated
- **Cronet transport**: provider ladder (HttpEngine → GMS → app-packaged → fallback → reflective Java provider), QUIC/HTTP2/Brotli
- **Typed errors**: failures surface as `ApifierException` subtypes instead of a generic `IOException`
- **Request observation**: `ApifierClient.events` is a `SharedFlow<RequestEvent>` carrying outcome,
  timing and byte counts for every attempt; a per-call `observe()` view sees only that call's event
- **Protected-domain trust check**: compares a configured host's system DNS answer against known-good public resolvers before the call runs
- **Encrypted cookies**: public-suffix-scoped cookie jar backed by a pluggable store, AES-GCM
  encrypted with an Android Keystore key (StrongBox or TEE where the device has one). A device
  with no usable Keystore drops cookies instead of writing them in cleartext
- **Streaming uploads**: multipart and single-file bodies stream from disk, never loading whole into memory
- **Retry and circuit breaker**: exponential backoff with per-host breakers. Retries are off
  until you raise `maxAttempts`; the breakers are on by default
- **DSL configuration**: Kotlin DSL for building a `NetworkConfig`

Cronet exposes no connection-pool controls and no separate connect/write timeouts, so the
library does not pretend to configure any of that. `read` and `call` are the only timeouts
that exist because they are the only ones Cronet actually enforces.

## Installation

Add JitPack repository:

```gradle
repositories {
    maven { url 'https://jitpack.io' }
}
```

Add dependency:

```gradle
dependencies {
    implementation 'com.github.Androidacy:android-apifier:3.0.0'
}
```

## Documentation

API documentation is available at [javadoc.jitpack.io](https://javadoc.jitpack.io/com/github/Androidacy/android-apifier/latest/javadoc/)

## Usage

```kotlin
import kotlin.time.Duration.Companion.seconds

val client = ApifierClient(context) {
    cronet {
        enableQuic = true
        enableHttp2 = true
        quicHint("api.example.com")
        cacheDirectory = context.cacheDir.resolve("cronet")
    }

    timeouts {
        read = 60.seconds
    }

    retry {
        retryOn5xx = true
    }

    // Same names as the per-call modifiers (client.maxAttempts(...), client.timeout(...)); a
    // call that sets neither uses these, and a call that does overrides them.
    maxAttempts(3)
    timeout(90.seconds)

    protectedDomains("api.example.com")
    cookieStorage(MyCookieStorage())
    header("User-Agent", "MyApp/1.0")
    dynamicHeader("Authorization") { getAuthToken() }
}

viewModelScope.launch {
    val response = client.get("https://api.example.com/data")
    response.use {
        if (it.isSuccessful) render(it.body.string())
    }
}

// In onCleared() or equivalent: release the engine, thread pools and network callback.
client.close()
```

`send`, `get`, `post`, `delete`, `head`, `download` and `upload` are `suspend` functions on
`Requester`; call them from a coroutine. Construction blocks too: selecting a Cronet provider can
reach Google Play services and wait on a Dynamite download, so build the client on a background
thread, or launch construction itself from a coroutine.

## Observation

`ApifierClient.events` is a `SharedFlow<RequestEvent>` with one event per attempt: outcome, error
code, response code, elapsed and time-to-first-byte, bytes sent and received, host, method,
attempt number, serving provider, and whether a retry follows. Collect it for every call the
client makes, or attach a per-call observer through `observe()` on a derived view to see just the
one event that ended that call.

```kotlin
scope.launch {
    client.events.collect { event -> log("${event.method} ${event.host} -> ${event.outcome}") }
}

val response = client.maxAttempts(1).observe { report(it) }.get("https://api.example.com/data")
```

## Protected Domains

For each configured host, apifier asks known-good public resolvers what the name resolves to and
compares that against the system resolver's answer. A host whose answers disagree, or that a
resolver could not be reached over a pinned-root connection, reports through
`protectedDomainStatus`; with enforcement on, a `FAIL` verdict refuses the call with
`ApifierException.DnsUntrusted`. Verdicts keep computing whether or not enforcement is on.

```kotlin
if (client.protectedDomainStatus("api.example.com") == TrustStatus.FAIL) warnUser()
client.setEnforceProtectedDomains(false)
```

## Errors

Every failure `send()` throws is an `ApifierException`: `Transport` for a Cronet network failure,
`CircuitOpen`, `Cancelled`, `CallTimeout`, `RedirectRefused`, `DnsUntrusted`, and `Unexpected` for
anything the pipeline does not model, which carries the original throwable as its cause. Each one
reports an `ErrorCode` and whether it is retryable.

## Cookie Storage

Implement `CookieStorage` interface:

```kotlin
class MyCookieStorage : CookieStorage {
    override fun getStringSet(key: String, defaultValue: Set<String>?) =
        encryptedPrefs.getStringSet(key, defaultValue)

    override fun putStringSet(key: String, value: Set<String>) =
        encryptedPrefs.edit { putStringSet(key, value) }

    override fun remove(key: String) =
        encryptedPrefs.edit { remove(key) }
}
```

## Progress Tracking

A request that sends a body and reads one reports both halves into the same sink, one at a time:
the upload completes before the download starts, so nothing needs to say which phase an update
belongs to. A body of unknown length reports progress but never reaches its total, since none is
known, and a retried upload counts from zero again.

Upload progress only reports for a file-backed body: `asRequestBody(File)`, or a multipart part
built from one. A body built from a `String` or `ByteArray`, including the `post(url, json)`
convenience, is small enough to sit fully in memory, and reporting it would jump the sink straight
to full before resetting for the download that follows, so it is left out. Download progress has
no such gate and always reports.

Build the sink with `extraBufferCapacity > 0`. A default `MutableSharedFlow<Progress>()` has no
buffer space, and its `tryEmit` returns `false` for every update, so it silently reports nothing.

```kotlin
val progress = MutableSharedFlow<Progress>(extraBufferCapacity = 64)
scope.launch {
    progress.collect { (bytesTransferred, contentLength) ->
        if (contentLength <= 0) return@collect
        updateProgressBar((bytesTransferred * 100 / contentLength).toInt())
    }
}

scope.launch {
    client.progress(progress).download(url).close()
    client.progress(progress).upload(url, files, fileNames).close()
}
```

## Security

TLS trust for API traffic runs through Cronet, which honors your app's
[Network Security Configuration](https://developer.android.com/privacy-and-security/security-config).
Configure trust anchors, certificate pinning, and cleartext policy there; the
library does not override them:

```xml
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set>
            <pin digest="SHA-256">base64EncodedPin==</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

Cookies are stored encrypted with a hardware-backed AES-GCM key when a `CookieStorage`
backend is configured.

## Migrating to 3.0.0

- `send()` (and `get`/`post`/`delete`/`head`/`download`/`upload`) is the call surface now: a
  `suspend fun` on `Requester` that returns the `Response` directly, in place of `enqueue`/`execute`.
- `Call`, `Call.enqueue`, `Call.execute`, `Call.cancel`, `Call.isCanceled` and `Call.Factory` are
  deprecated; they still work but are removed in 4.0. `Callback` itself is not deprecated, since
  `Call.enqueue` still needs somewhere to report to until it is gone.
- If you keep using callbacks in the meantime: callbacks run on the client's worker pool, and the
  body handed to `onResponse` is still streaming when the callback fires. Post to your own handler
  before touching the UI, read or close the body, and do not treat the callback returning as the
  end of the call: the client stays active until the body ends.
- `ProgressListener` and `ProgressDirection` are gone. `progress(sink)` on `Requester` (or
  `download`/`upload`'s `progress` parameter on the deprecated callback surface) takes a
  `MutableSharedFlow<Progress>`, built with `extraBufferCapacity > 0`; see
  [Progress Tracking](#progress-tracking). `Progress` carries no direction, since a call's upload
  and download phases never interleave.
- `addObserver`/`removeObserver` are deprecated in favour of `ApifierClient.events`, a
  `SharedFlow<RequestEvent>`; see [Observation](#observation).
- `ResponseBody.source()` and `byteStream()` are deprecated in favour of the suspend
  `ResponseBody.bytes()`/`string()`, which read the whole body on `Dispatchers.IO` instead of
  blocking the calling thread.
- `NoRetry` and `Request.Builder.noRetry()` are gone; `maxAttempts(1)`, the default, replaces them.
- `retry { maxAttempts }` and `timeouts { call }` are gone from the DSL; the top-level
  `NetworkConfigBuilder.maxAttempts(count)`/`timeout(duration)` replace them, and are also the
  per-call modifiers on `Requester`.
- Failures arrive as `ApifierException` subtypes. Code matching on the old flat
  `IOException("Cronet request failed")` message needs to switch on `errorCode` instead.
- `ApifierClient` is `Closeable` and owns an engine, thread pools and a network callback. Call
  `close()` when you are done with it.
- DoH resolution and the OkHttp interceptor are gone. Configure TLS trust through your app's
  Network Security Configuration, and protected-domain checking through `protectedDomains(...)`.
- `protectedDomains(...)` rejects a hostname with a trailing dot, and the client constructor throws
  on it. Pass `api.example.com`, not `api.example.com.`

## Requirements

- Android API 26+
- Kotlin 2.2+

## License

```
Copyright 2025 Androidacy

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
