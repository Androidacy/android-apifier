# Android Apifier

[![Release](https://img.shields.io/github/v/release/Androidacy/android-apifier?sort=semver)](https://github.com/Androidacy/android-apifier/releases/latest)
[![](https://jitpack.io/v/Androidacy/android-apifier.svg)](https://jitpack.io/#Androidacy/android-apifier)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

HTTP and API networking library for Android, built directly on Cronet.

## Features

- **Cronet transport**: provider ladder (HttpEngine → GMS → app-packaged → fallback → reflective Java provider), QUIC/HTTP2/Brotli
- **Typed errors**: failures surface as `ApifierException` subtypes instead of a generic `IOException`
- **Request observation**: per-client and per-call observers see outcome, timing and byte counts for every attempt
- **Protected-domain trust check**: compares a configured host's system DNS answer against known-good public resolvers before the call runs
- **Encrypted cookies**: public-suffix-scoped cookie jar backed by a pluggable store, AES-GCM
  encrypted with an Android Keystore key (StrongBox or TEE where the device has one). A device
  with no usable Keystore drops cookies instead of writing them in cleartext
- **Streaming uploads**: multipart and single-file bodies stream from disk rather than loading into memory
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

client.get("https://api.example.com/data", object : Callback {
    override fun onResponse(call: Call, response: Response) {
        // Handle response
    }

    override fun onFailure(call: Call, e: IOException) {
        // Handle error
    }
})

// Release the engine, thread pools and network callback when the client is no longer needed.
client.close()
```

Construction blocks: selecting a Cronet provider can reach Google Play services and wait on a
Dynamite download, so build the client on a background thread.

## Observation

Observers see one event per attempt: outcome, error code, response code, elapsed and
time-to-first-byte, bytes sent and received, host, method, attempt number, serving provider, and
whether a retry follows. A client-wide observer sees every call; a per-call observer set through
`observe` on a derived view sees exactly one event, the attempt that ended its call.

```kotlin
client.addObserver { event -> log("${event.method} ${event.host} -> ${event.outcome}") }

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

Every failure that reaches a callback or a blocking `execute()` is an `ApifierException`:
`Transport` for a Cronet network failure, `CircuitOpen`, `Cancelled`, `CallTimeout`,
`RedirectRefused`, `DnsUntrusted`, and `Unexpected` for anything the pipeline does not model,
which carries the original throwable as its cause. Each one reports an `ErrorCode` and whether it
is retryable.

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

client.download(url, progress, callback)
client.upload(url, files, fileNames, progress, callback)
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

- Callbacks run on the client's worker pool, and the body handed to `onResponse` is still
  streaming when the callback fires. Post to your own handler before touching the UI, read or
  close the body, and do not treat the callback returning as the end of the call: the client stays
  active until the body ends.
- `ProgressListener` is gone. `download` and `upload` now take a `MutableSharedFlow<Progress>`,
  built with `extraBufferCapacity > 0`; see [Progress Tracking](#progress-tracking).
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
