# Changelog

## 3.0.0

### Call surface

- `send()` (and `get`/`post`/`delete`/`head`/`download`/`upload`) is the call surface now: a
  `suspend fun` on `Requester` that returns the `Response` directly, in place of `enqueue`/`execute`.
- `Call`, `Call.enqueue`, `Call.execute`, `Call.cancel`, `Call.isCanceled` and `Call.Factory` are
  deprecated. They still work but are removed in 4.0. `Callback` itself is not deprecated, since
  `Call.enqueue` still needs somewhere to report to until it is gone.
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

### Progress and observation

- `ProgressListener` and `ProgressDirection` are gone. `progress(sink)` on `Requester` (or
  `download`/`upload`'s `progress` parameter on the deprecated callback surface) takes a
  `MutableSharedFlow<Progress>`, built with `extraBufferCapacity > 0`; see the README's
  [Progress Tracking](README.md#progress-tracking) section. `Progress` carries no direction, since
  a call's upload and download phases never interleave.
- `addObserver`/`removeObserver` are deprecated in favour of `ApifierClient.events`, a
  `SharedFlow<RequestEvent>`; see the README's [Observation](README.md#observation) section.
- `ResponseBody.source()` and `byteStream()` are deprecated in favour of the suspend
  `ResponseBody.bytes()`/`string()`, which read the whole body on `Dispatchers.IO` instead of
  blocking the calling thread.

### DNS trust

- DoH resolution and the OkHttp interceptor are gone. Configure TLS trust through your app's
  Network Security Configuration.
- `NetworkConfigBuilder.protectedDomains(...)`, `ApifierClient.protectedDomainStatus` and
  `ApifierClient.setEnforceProtectedDomains` are gone, along with the DNS comparison behind them.
  `ensureTrustworthyResolver(true)` and `isResolverTrustworthy()` replace them with
  host-independent resolver qualification, and `hostIpPins { ... }` covers a host whose expected
  addresses you already know; see the README's
  [Resolver Qualification](README.md#resolver-qualification) section.
