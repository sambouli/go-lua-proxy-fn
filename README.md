# go-lua-proxy-fn

> **What this repo is.** This is one half of an A/B comparison. The same task —
> "build a Go reverse proxy with a per-request Lua scripting API" — was given to
> two different models, and each result was kept in its own repository so the
> outcomes can be read side by side:
>
> | Repo | Produced by |
> |---|---|
> | [go-lua-proxy](https://github.com/sambouli/go-lua-proxy) | the baseline model |
> | **go-lua-proxy-fn** (this repo) | **QFN** (Qwen3.8-Flash-Next), hence the `-fn` suffix |
>
> The two are independent implementations of the same brief, not a fork and an
> upstream. Nothing here is intended to replace the other repo — compare them on
> structure, test coverage, docs and edge-case handling. The baseline side names its own model in its README.

A single-binary HTTP reverse proxy in Go that runs **Lua scripts per request**
and exposes a Lua API for regular reverse-proxy operations: client-IP
resolution, request/response header rewriting, path/query rewrites, body
rewrites, redirects, and short-circuit aborts.

Built on `net/http/httputil.ReverseProxy` +
[gopher-lua](https://github.com/yuin/gopher-lua). One dependency, no cgo.

## Quick start

```bash
go build -o go-lua-proxy-fn .

LISTEN_ADDR=:8080 \
UPSTREAM=http://127.0.0.1:9000 \
LUA_SCRIPTS=./examples/clientip-and-day.lua \
./go-lua-proxy-fn
```

The example rule (`examples/clientip-and-day.lua`) echoes the real client IP
and the current UTC day of week into response headers:

```lua
proxy.setResponseHeader("X-Client-IP", proxy.clientIP())
proxy.setResponseHeader("X-Day-Of-Week", os.date("!%A"))
proxy.setRequestHeader("X-From-Lua", "lua-rule-ran")
```

## Configuration (environment variables)

| Variable              | Default                | Effect                                            |
|-----------------------|------------------------|---------------------------------------------------|
| `LISTEN_ADDR`         | `:8080`                | Listen address                                    |
| `UPSTREAM`            | `http://localhost:9090`| Backend URL (scheme must be http/https)           |
| `LUA_SCRIPTS`         | *(none)*               | Comma-separated list of Lua files, run in order   |
| `TRUST_PROXY_HEADERS` | `false`                | Honor inbound `X-Forwarded-*` / `X-Real-Ip`       |

`GET /__proxy_stats__` returns aggregate counters as JSON.

## Lua API

Every request gets a fresh Lua state with one global table, `proxy`.
Scripts run sequentially before forwarding; if one calls `abort()`/`redirect()`
the chain stops and the upstream is never contacted. A script error returns 500.

### Request info (read-only)
```lua
proxy.request.method / .path / .rawPath / .proto
proxy.getHeader(name)      -- request header (multi-values joined with ", ")
proxy.getQuery(name)       -- URL query parameter
proxy.clientIP()           -- X-Real-Ip → XFF[0] → socket peer (headers only when trusted)
proxy.remoteAddr()         -- raw peer address incl. port
proxy.scheme()             -- "http"/"https" (TLS or trusted X-Forwarded-Proto)
proxy.host()               -- Host header
proxy.upstreamURL()        -- configured UPSTREAM
```

### Request mutation (applied before forwarding)
```lua
proxy.setRequestHeader(name, value)
proxy.addRequestHeader(name, value)
proxy.removeRequestHeader(name)
proxy.setPath(path)
proxy.setQuery(key, value)
proxy.getBody() / proxy.setBody(str)
```

### Response manipulation (merged into the proxied response)
```lua
proxy.setStatus(code)
proxy.setResponseHeader(name, value)
```

### Short-circuit
```lua
proxy.abort(status?, body?)          -- default 403 "blocked by script"
proxy.redirect(location, status?)    -- default 302
```

### Date/time & misc
```lua
os.time([tbl]) -> epoch seconds      -- tbl form: {year,month,day,hour,min,sec} (UTC)
os.date(fmt[, epoch])                -- "!%A", "%Y-%m-%d", "*t" table, strftime subset
os.clock()                           -- CPU-ish seconds since process start
proxy.jsonDecode(s) / proxy.jsonEncode(t)
proxy.log(msg)
```

## Security notes

- Inbound `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` and
  `X-Real-Ip` are **deleted** from the forwarded request and only consulted by
  `clientIP()`/`scheme()` when `TRUST_PROXY_HEADERS=true`. Set it only when a
  real load balancer sits in front, otherwise clients forge their own source IP.
- The proxy itself sets proper `X-Forwarded-For`/`-Host`/`-Proto` toward the
  upstream via `SetXForwarded()`.
- Streaming-safe: `FlushInterval=-1`, so SSE/long-poll responses flush through.

## Tests

```bash
go test ./...                 # unit + in-process end-to-end tests
bash scripts/verify_e2e.sh <binary> <scratchdir>   # full rig against a real process
```

The e2e rig starts a dummy Python web server, launches the compiled proxy with
a Lua rule that fetches the client IP and the day of the week into response
headers, then asserts the client sees `X-Client-IP: 127.0.0.1`,
`X-Day-Of-Week` matching `date -u +%A`, forged-XFF rejection, header
pass-through both directions, and clean `SIGTERM` shutdown — currently
**10 passed, 0 failed**.

## Limitations

- No cross-request Lua state (fresh VM per request); use an external store for
  rate limits/caches.
- Request bodies buffered up to 10 MB for Lua inspection.
- Single upstream host, not a load balancer.

## Comparing against `go-lua-proxy`

Both repos solve the same brief, so the differences are about engineering choices
rather than missing features. Points worth checking when reading them side by side:

- **Configuration style** — env vars here (`LISTEN_ADDR`, `UPSTREAM`,
  `LUA_SCRIPTS`) vs the other repo's flags and `.lua` file layout.
- **Lua lifecycle** — this build starts a fresh VM per request; check whether the
  other shares state across requests, and what that means for isolation.
- **Body handling** — request bodies are buffered up to 10 MB here before Lua sees
  them; compare the limit and the streaming behaviour.
- **Test strategy** — unit + in-process end-to-end tests plus a `scripts/verify_e2e.sh`
  rig that drives a real compiled binary against a dummy origin server.
- **Client-IP trust** — forged `X-Forwarded-For` rejection is asserted here; see how
  the other decides which proxies to trust.

Neither is meant to be canonical. Pick whichever fits, or read both as reference
implementations of the same idea.
