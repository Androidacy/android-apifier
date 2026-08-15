# Changelog

## 3.0.0

### Call surface

- `send()` (and `get`/`post`/`delete`/`head`/`download`/`upload`) is the call surface now: a
  `suspend fun` on `Requester` that returns the `Response` directly, in place of `enqueue`/`execute`.
- `Call`, `Call.enqueue`, `Call.execute`, `Call.cancel`, `Call.isCanceled` and `Call.Factory` are
  deprecated. They still work but are removed in 4.0. `Callback` itself is not deprecated; it
  keeps receiving the result of `Call.enqueue` until that goes away too.
- If you keep using callbacks in the meantime: callbacks run on the client's worker pool, and the
  body handed to `onResponse` is still streaming when the callback fires. Post to your own handler
  before touching the UI, read or close the body, and do not treat the callback returning as the
  end of the call. The client stays active until the body ends.
- `NoRetry` and `Request.Builder.noRetry()` are gone. `maxAttempts(1)`, the default, replaces them.
- `retry { maxAttempts }` and `timeouts { call }` are gone from the DSL. The top-level
  `NetworkConfigBuilder.maxAttempts(count)`/`timeout(duration)` replace them, and are also the
  per-call modifiers on `Requester`.
- Failures arrive as `ApifierException` subtypes. Code matching on the old flat
  `IOException("Cronet request failed")` message needs to switch on `errorCode` instead.
- `ApifierClient` is `Closeable` and owns an engine, thread pools and a network callback. Call
  `close()` when you are done with it.
- `close()` blocks for up to twelve seconds while it drains in-flight calls, stops the engine and
  flushes observation, so keep it off the main thread. It throws `IllegalStateException` when it is
  called from a `Callback` or a `RequestObserver` of the same client; close from a thread of your
  own instead.

### Progress and observation

- `ProgressListener` and `ProgressDirection` are gone. `progress(sink)` on `Requester` (or
  `download`/`upload`'s `progress` parameter on the deprecated callback surface) takes a
  `MutableSharedFlow<Progress>`, built with `extraBufferCapacity > 0`; see the README's
  [Progress Tracking](README.md#progress-tracking) section. `Progress` carries no direction.
- `addObserver`/`removeObserver` are deprecated in favour of `ApifierClient.events`, a
  `SharedFlow<RequestEvent>`; see the README's [Observation](README.md#observation) section.

### Streaming and per-call headers

- `ResponseBody.byteStream()` is gone and `source()` is no longer public. Read a body with
  `ResponseBody.read { source -> ... }`, which hands a scoped `BufferedSource` to the block and
  closes the body when the block returns or throws, or with `ResponseBody.writeTo(file)`, which
  streams straight to disk. Neither holds the body in memory.
- `ResponseBody.bytes()` carries `@Discouraged` and `@Deprecated`, with no removal version attached
  and none planned. `string()` carries neither annotation and is not deprecated. Both still work;
  either one reads the whole body into memory before returning it, so a large or unknown-length
  response belongs on `read` or `writeTo` instead.
- `ResponseBody.json<T>()` decodes a JSON body straight off its source with `kotlinx.serialization`,
  and `ResponseBody.lines()` returns a `Flow<String>` of the body one line at a time. Both close
  the body when they finish. `json` needs `org.jetbrains.kotlinx:kotlinx-serialization-json` and
  `org.jetbrains.kotlinx:kotlinx-serialization-json-okio` on your own classpath: apifier compiles
  against them but does not bundle them.
- `Requester.header(name, value)` attaches a header to a single call without touching the
  client's own configuration:
  ```kotlin
  client.header("X-Request-Id", requestId).get(url)
  ```
  A header already present on the `Request` passed to `send()` wins over this, and this wins over
  a same-named header configured client-wide.
- `Response.successOrThrow()` returns the response on a 2xx status and otherwise closes its body
  and throws `ApifierException.HttpError`, which carries the status in its `code` property. Use it
  in place of a hand-written `isSuccessful` check.
- `Response.retryAfter` parses the `Retry-After` header in either form the HTTP spec allows,
  a delta in seconds or an HTTP-date, and returns the remaining `kotlin.time.Duration`. A date
  already in the past, or a negative delta a malformed server sent, both come back as
  `Duration.ZERO`. The header returns `null` when it is missing or in neither form.

### DNS trust

- DoH resolution and the OkHttp interceptor are gone. Configure TLS trust through your app's
  Network Security Configuration.
- `NetworkConfigBuilder.protectedDomains(...)`, `ApifierClient.protectedDomainStatus` and
  `ApifierClient.setEnforceProtectedDomains` are gone, along with the DNS comparison behind them.
  `ensureTrustworthyResolver(true)` and `isResolverTrustworthy()` replace them with
  host-independent resolver qualification, and `hostIpPins { ... }` covers a host whose expected
  addresses you already know; see the README's
  [Resolver Qualification](README.md#resolver-qualification) section.
- `AddressClassifier.classify` no longer classifies a zone-suffixed address (`fe80::1%wlan0`) or an
  IPv4-mapped address (`::ffff:1.2.3.4`); both now return `INVALID`. Strip the zone suffix, or
  unwrap the mapped address to its IPv4 form, before calling `classify` if you need an answer for
  either shape.

### Redirects

- A redirect to a different host is now refused while the request carries `Authorization` or
  `Proxy-Authorization`, the same way it already was for `Cookie`. A caller that relied on such a
  redirect succeeding needs to authenticate again after following the redirect itself.

### Cookies

- A `Set-Cookie` with neither `Expires` nor `Max-Age` is now a session cookie: held in memory for
  the client's lifetime and never written to your `CookieStorage`. `Cookie.persistent` tells the
  two apart. Existing persisted cookies are unaffected and keep loading as before.
- `ApifierClient.clearCookies()` drops every cookie the client holds, in memory and in storage.
  Call it on logout. `CookieJar.clear()` is a new interface member with a no-op default, so a
  custom `CookieJar` you already wrote keeps compiling.
- `SecureCookieJar`'s constructor now takes a `PublicSuffixList` alongside your `CookieStorage`.
  `ApifierClient` builds this for you; only a caller constructing `SecureCookieJar` directly needs
  to pass one, with `PublicSuffixList.load(context)`. Cookies already in your `CookieStorage` load
  the same as before; nothing about what is persisted changes.
