# Android Apifier

[![](https://jitpack.io/v/Androidacy/android-apifier.svg)](https://jitpack.io/#Androidacy/android-apifier)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

HTTP and API networking library for Android with Cronet and OkHttp.

## Features

- **Cronet Integration**: Multi-provider Cronet support (GMS → Native → Java fallback)
- **HTTP/3 & QUIC**: Modern protocol support for improved performance
- **Configurable Retry**: Built-in exponential backoff and retry logic
- **Progress Tracking**: Download/upload progress monitoring
- **Secure Cookies**: Encrypted cookie storage with customizable backend
- **Connection Optimization**: Mobile-optimized connection pooling and timeouts
- **DSL Configuration**: Kotlin DSL for clean, type-safe configuration

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
    implementation 'com.github.Androidacy:android-apifier:1.0.0'
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
        connect = 5.seconds
        read = 60.seconds
    }

    retry {
        maxAttempts = 3
        retryOn5xx = true
    }

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
```

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

## Requirements

- Android API 26+
- Kotlin 2.2+
- OkHttp 5.3+

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
