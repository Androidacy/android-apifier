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
- **Encrypted cookies**: public-suffix-scoped cookie jar backed by a pluggable, hardware-encrypted store
- **Streaming uploads**: multipart and single-file bodies stream from disk rather than loading into memory
- **Retry and circuit breaker**: exponential backoff with per-host breakers
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
val client = ApifierClient(context) {
    cronet {
        enableQuic = true
        enableHttp2 = true
        quicHint("api.example.com")
        cacheDirectory = context.cacheDir.resolve("cronet")
    }

    timeouts {
        read = 60.seconds
        call = 90.seconds
    }

    retry {
        maxAttempts = 3
        retryOn5xx = true
    }

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

```kotlin
client.download(url, object : ProgressListener {
    override fun update(bytesRead: Long, contentLength: Long, done: Boolean) {
        val progress = (bytesRead * 100 / contentLength).toInt()
        updateProgressBar(progress)
    }
}, callback)
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
