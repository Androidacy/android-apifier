# Android Apifier

[![Release](https://img.shields.io/github/v/release/Androidacy/android-apifier?sort=semver)](https://github.com/Androidacy/android-apifier/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

HTTP and API networking library for Android, built directly on Cronet.

Upgrading from 2.x is a breaking change. [CHANGELOG.md](CHANGELOG.md) names every symbol that was
removed or renamed, so a build error can be searched for by the symbol it names.

## Features

- **Coroutine call surface**: `send()` and its shorthands (`get`, `post`, `delete`, `head`,
  `download`, `upload`) are `suspend` functions on `Requester`; the callback-based `Call`/`Callback`
  surface still works but is deprecated
- **Cronet transport**: provider ladder (HttpEngine → GMS → app-packaged → fallback → reflective Java provider), QUIC/HTTP2/Brotli
- **Typed errors**: failures surface as `ApifierException` subtypes instead of a generic `IOException`
- **Request observation**: `ApifierClient.events` is a `SharedFlow<RequestEvent>` carrying outcome,
  timing and byte counts for every attempt; a per-call `observe()` view sees only that call's event
- **Resolver qualification**: checks the platform's DNS resolver against names whose correct answers are known, independent of any host the app calls, and rechecks after every network change; optionally refuses calls while those checks fail, and per-host IP pins for hosts where you know the expected addresses
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

Add the Androidacy Maven registry:

```gradle
repositories {
    maven { url 'https://git.androidacy.com/api/packages/Androidacy/maven' }
}
```

Add dependency:

```gradle
dependencies {
    implementation 'com.github.Androidacy:android-apifier:3.0.1'
}
```

Releases up to 3.0.0 are also on JitPack. Anything newer is published only to the registry above.

## Documentation

API documentation ships as the `javadoc` artifact alongside each release.

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

    ensureTrustworthyResolver(true)
    hostIpPins {
        pin("api.example.com", "203.0.113.10")
    }
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

## Resolver Qualification

Each client qualifies the platform's DNS resolver once and caches the verdict until the network
changes: names that must not resolve, and public names that must resolve to public address space.
A resolver that cannot answer both consistently is untrustworthy, which catches one that is broadly
wrong or hijacked. A second check then qualifies the host the call is for on its own, requiring
every address it resolves to be public, so a single hostname being sinkholed is caught while the
rest of DNS behaves normally. Neither check authenticates an answer against a third-party DNS
provider, since a geo-DNS fronted host can see different, equally legitimate answers from different
resolvers. The consequence of the per-host check is that enforcement refuses any host on private
address space: a LAN device, a VPN-reachable staging server, a `.local` name and an internal API on
RFC 1918 space all fail while it is on.

```kotlin
val trustworthy = client.isResolverTrustworthy()
```

Set `ensureTrustworthyResolver(true)` in the DSL to refuse calls while the resolver fails
qualification; left off, the checks still run but nothing is blocked on them.

For a host where you know the expected addresses, declare a pin instead:

```kotlin
hostIpPins {
    pin("api.example.com", "203.0.113.10")
}
```

Declaring any pin turns on enforcement for the whole client, regardless of
`ensureTrustworthyResolver`. The declared set is the whole set: a pinned host is refused with
`ApifierException.DnsUntrusted` unless every address it resolves to is among the declared ones, so
an answer adding an undeclared address to a declared one is refused too. Pins are unsuited to a
host behind geo-DNS fronting, where legitimate answers differ by resolver vantage point, and a pin
outliving an address migration refuses every call to that host until the pin is updated.

The pin is checked against a resolution this library performs. Cronet resolves the host again for
the connection, so a pin narrows the window without closing it.

## Errors

`send()` throws `ApifierException` for every call failure, `IllegalStateException` if the client
is already closed, and `CancellationException` if the calling coroutine is cancelled. The
`ApifierException` subtypes are `Transport` for a Cronet network failure, `CircuitOpen`,
`Cancelled`, `CallTimeout`, `RedirectRefused`, `DnsUntrusted`, `HttpError` for a non-2xx response
passed through `successOrThrow()`, and `Unexpected` for anything the pipeline does not model,
which carries the original throwable as its cause. Each one reports an `ErrorCode` and whether
it is retryable.

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
