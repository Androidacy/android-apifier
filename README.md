# Android Apifier

[![Release](https://img.shields.io/gitea/v/release/Androidacy/android-apifier?gitea_url=https%3A%2F%2Fgit.androidacy.com)](https://git.androidacy.com/Androidacy/android-apifier/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

HTTP and API networking library for Android, built directly on Cronet.

Upgrading from 2.x is a breaking change. [CHANGELOG.md](CHANGELOG.md) lists every removed and
renamed symbol.

## Install

```gradle
repositories {
    maven { url 'https://git.androidacy.com/api/packages/Androidacy/maven' }
}

dependencies {
    implementation 'com.github.Androidacy:android-apifier:3.0.2'
}
```

Releases up to 3.0.0 are also on JitPack. Anything newer is published only to the registry above.

## Quick start

```kotlin
val client = ApifierClient(context)

viewModelScope.launch {
    client.get("https://api.example.com/data").use { response ->
        if (response.isSuccessful) render(response.body.string())
    }
}

client.close()
```

`send`, `get`, `post`, `delete`, `head`, `download` and `upload` are `suspend` functions on
`Requester`. Constructing the client blocks — provider selection can reach Google Play services and
wait on a Dynamite download — so build it off the main thread. `close()` releases the engine,
thread pools and network callback.

## Features

- `suspend` call surface; the `Call`/`Callback` API still works but is deprecated
- Cronet transport with QUIC, HTTP/2 and Brotli, over a provider ladder: `HttpEngine`, GMS,
  app-packaged, fallback, reflective Java provider
- Typed failures — `ApifierException` subtypes rather than a bare `IOException`
- Per-attempt request events: outcome, timing, byte counts
- DNS resolver qualification and per-host IP pinning
- Public-suffix-scoped cookie jar, AES-GCM encrypted under an Android Keystore key
- Streaming multipart and file uploads
- Exponential backoff with per-host circuit breakers
- Kotlin DSL for `NetworkConfig`

## Configuration

```kotlin
val client = ApifierClient(context) {
    cronet {
        enableQuic = true
        enableHttp2 = true
        quicHint("api.example.com")
        cacheDirectory = context.cacheDir.resolve("cronet")
    }

    timeouts { read = 60.seconds }
    retry { retryOn5xx = true }

    maxAttempts(3)
    timeout(90.seconds)

    ensureTrustworthyResolver(true)
    hostIpPins { pin("api.example.com", "203.0.113.10") }
    cookieStorage(MyCookieStorage())
    header("User-Agent", "MyApp/1.0")
    dynamicHeader("Authorization") { getAuthToken() }
}
```

`maxAttempts` and `timeout` are also per-call modifiers (`client.maxAttempts(1).get(url)`); a call
that sets neither uses the client's values.

`read` and `call` are the only timeouts. Retries are off until you raise `maxAttempts`; circuit
breakers are on by default.

## Observation

`ApifierClient.events` is a `SharedFlow<RequestEvent>` with one event per attempt, carrying
outcome, error code, response code, elapsed and time-to-first-byte, bytes sent and received, host,
method, attempt number, serving provider, and whether a retry follows.

```kotlin
scope.launch {
    client.events.collect { event -> log("${event.method} ${event.host} -> ${event.outcome}") }
}

client.maxAttempts(1).observe { report(it) }.get("https://api.example.com/data")
```

`observe()` sees only the event that ended that call.

## DNS

Each client qualifies the platform resolver once per network: names that must not resolve, and
public names that must resolve to public address space. Each call's host is then checked on its
own, requiring every address it resolves to be public.

```kotlin
val trustworthy = client.isResolverTrustworthy()
```

`ensureTrustworthyResolver(true)` refuses calls while qualification fails. Left off, the checks
still run but block nothing.

Enforcement refuses any host on private address space — LAN devices, VPN-reachable staging,
`.local` names and RFC 1918 APIs all fail while it is on.

For a host with known addresses, pin instead:

```kotlin
hostIpPins { pin("api.example.com", "203.0.113.10") }
```

Any pin turns on enforcement for the whole client. The declared set is the whole set: a pinned host
is refused with `ApifierException.DnsUntrusted` unless every resolved address is declared. Pins
suit neither geo-DNS fronted hosts nor address migrations, and are checked against this library's
resolution — Cronet resolves again to connect, so a pin narrows the window rather than closing it.

## Errors

`send()` throws `ApifierException` on failure, `IllegalStateException` if the client is closed, and
`CancellationException` if the calling coroutine is cancelled. Every `ApifierException` reports an
`ErrorCode` and whether it is retryable.

| Subtype | Raised when |
|---|---|
| `Transport` | Cronet network failure |
| `CircuitOpen` | Host breaker is open |
| `Cancelled` | Call was cancelled |
| `CallTimeout` | Call exceeded its timeout |
| `RedirectRefused` | Redirect was not followed |
| `DnsUntrusted` | Resolver or pin check failed |
| `HttpError` | Non-2xx passed through `successOrThrow()` |
| `Unexpected` | Anything unmodelled; carries the original as its cause |

## Cookies

Implement `CookieStorage`:

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

Cookies are encrypted with a hardware-backed AES-GCM key, using StrongBox or the TEE where the
device has one. A device with no usable Keystore drops cookies rather than storing them in
cleartext.

## Progress

```kotlin
val progress = MutableSharedFlow<Progress>(extraBufferCapacity = 64)
scope.launch {
    progress.collect { (bytesTransferred, contentLength) ->
        if (contentLength > 0) updateProgressBar((bytesTransferred * 100 / contentLength).toInt())
    }
}

scope.launch {
    client.progress(progress).download(url).close()
    client.progress(progress).upload(url, files, fileNames).close()
}
```

Build the sink with `extraBufferCapacity > 0`. A default `MutableSharedFlow<Progress>()` reports
nothing at all.

Upload and download report into the same sink, upload first. Upload progress requires a file-backed
body — `asRequestBody(File)` or a multipart part built from one; `String` and `ByteArray` bodies
report nothing. A body of unknown length never reaches its total, and a retried upload restarts
from zero.

## Security

TLS trust runs through Cronet, which honors your app's
[Network Security Configuration](https://developer.android.com/privacy-and-security/security-config).
Configure trust anchors, certificate pinning and cleartext policy there.

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

## Requirements

- Android 8.0 (API 26)
- Java 21
- Kotlin 2.4

## Documentation

API documentation ships as the `javadoc` artifact alongside each release.

## License

Apache 2.0. See [LICENSE](LICENSE).
