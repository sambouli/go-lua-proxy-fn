// go-lua-proxy-fn is a lightweight HTTP reverse proxy that executes Lua scripts
// per-request, giving programmatic control over routing, auth, headers, body
// transformation, and more.
//
// # Configuration
//
// The proxy is configured entirely via environment variables:
//
//	LISTEN_ADDR=:8080        Address to listen on (default :8080)
//	UPSTREAM=http://backend  Backend URL to proxy to (required)
//	LUA_SCRIPTS=./a.lua,...  Comma-separated list of Lua script files
//	TRUST_PROXY_HEADERS=false  Honor inbound X-Forwarded-* / X-Real-Ip (default false)
//
// # Lua API
//
// Each loaded script runs inside a fresh Lua state with one global table: `proxy`.
// Every request creates a new Lua state; globals do NOT persist between requests.
//
// ## Request info (read-only)
//
//	proxy.request.method   — "GET", "POST", etc.
//	proxy.request.path     — URL path
//	proxy.request.rawPath  — path as received (encoded chars preserved)
//	proxy.request.proto    — "HTTP/1.1", "HTTP/2.0"
//
//	proxy.getHeader(key)       — request header value (comma-joined for multi-value)
//	proxy.getQuery(key)        — URL query parameter value
//	proxy.clientIP()           — real client IP (X-Real-Ip → X-Forwarded-For[0] → RemoteAddr)
//	proxy.remoteAddr()         — raw peer address, e.g. "127.0.0.1:54321"
//	proxy.scheme()             — "http" or "https" (respects X-Forwarded-Proto, checks TLS)
//	proxy.host()               — Host header value
//	proxy.upstreamURL()        — the configured UPSTREAM value
//
// ## Request mutation (applied before forwarding upstream)
//
//	proxy.setRequestHeader(name, value) — set a request header sent upstream
//	proxy.addRequestHeader(name, value) — append a request header
//	proxy.removeRequestHeader(name)     — drop a request header
//	proxy.setPath(path)                 — rewrite the upstream request path
//	proxy.setQuery(key, value)          — set a URL query parameter
//
//	X-Forwarded-For / X-Real-Ip are only honored by clientIP() when
//	TRUST_PROXY_HEADERS=true; otherwise they are treated as untrusted and
//	clientIP() falls back to the socket peer address.
//
// ## Response manipulation (merged into proxied response)
//
// These set fields on api.Response without short-circuiting. Headers are merged
// into the upstream response by ModifyResponse.
//
//	proxy.setStatus(code)                    — set HTTP status code
//	proxy.setResponseHeader(name, value)     — add a response header
//
// ## Body manipulation
//
//	proxy.getBody()    — return the request body as a string
//	proxy.setBody(str) — replace the request body before forwarding
//
// ## Short-circuit (bypass upstream entirely)
//
// These methods stop the request from reaching the backend and send a response directly.
//
//	proxy.redirect(location, statusCode?)  — redirect (default 302)
//	proxy.abort(statusCode, body?)         — abort with custom status + body (default 403)
//
//	Example: proxy.abort(200, `{"status":"ok"}`)
//	Example: proxy.redirect("/login", 302)
//
// ## JSON helpers
//
//	proxy.jsonDecode(str) → table, error  — parse JSON string → Lua table
//	proxy.jsonEncode(table) → str, error  — encode Lua table → JSON string
//
// Numbers stay as numbers (not strings), booleans stay boolean, nil stays nil.
//
// ## Logging
//
//	proxy.log(msg) — prints to proxy stderr log
//
// ## Date/time
//
// os.time([table]) — current epoch seconds, or formatted via os.date
// os.date(fmt[, time]) — "!*t"/"*t" return a table; other fmt uses strftime
// os.clock() — CPU seconds since process start
// math.random / math.randomseed — available but seeded randomly per state
//
// Example (day of the week as a response header):
//
//	local dow = os.date("!%A")            -- e.g. "Friday" in UTC
//	proxy.setResponseHeader("X-Day-Of-Week", dow)
//
// # Stats endpoint
//
// GET /__proxy_stats__ returns JSON with total_requests, status_codes, avg_latency_ms, etc.
//
// # Limitations
//
//   - No cross-request state: each request gets a new Lua state. For persistent state
//     (rate limiting, caching), use an external store reachable via HTTP from Lua.
//   - Body size limit: request bodies are read up to 10 MB before being passed to Lua.
//   - Single upstream: this is a single-host reverse proxy, not a load balancer.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// --- Config ---

// Config holds the proxy configuration loaded from environment variables.
type Config struct {
	ListenAddr        string            // Address to listen on (LISTEN_ADDR)
	Upstream          string            // Backend URL to proxy to (UPSTREAM)
	LuaScripts        map[string]string // Map of file path -> source content (LUA_SCRIPTS)
	ScriptTimeout     time.Duration     // Max execution time per script (reserved)
	TrustProxyHeaders bool              // Honor inbound X-Forwarded-* / X-Real-Ip (TRUST_PROXY_HEADERS)
}

// loadConfig reads configuration from environment variables.
func loadConfig() Config {
	cfg := Config{
		ListenAddr:        getEnv("LISTEN_ADDR", ":8080"),
		Upstream:          getEnv("UPSTREAM", "http://localhost:9090"),
		ScriptTimeout:     5 * time.Second,
		LuaScripts:        make(map[string]string),
		TrustProxyHeaders: strings.EqualFold(os.Getenv("TRUST_PROXY_HEADERS"), "true"),
	}
	if scripts := os.Getenv("LUA_SCRIPTS"); scripts != "" {
		for _, p := range strings.Split(scripts, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			data, err := os.ReadFile(p)
			if err != nil {
				log.Fatalf("read lua script %s: %v", p, err)
			}
			cfg.LuaScripts[p] = string(data)
		}
	}
	return cfg
}

// getEnv returns the value of the environment variable named by key,
// or fallback if the variable is unset or empty.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// LVIsNil checks if a stack value is nil (using negative index).
// This is needed because gopher-lua's IsNoneOrNil doesn't work with negative indices.
func LVIsNil(L *lua.LState, idx int) bool {
	v := L.Get(idx)
	return v == lua.LNil
}

// --- Proxy state ---

// ProxyState holds shared statistics across all requests.
type ProxyState struct {
	mu       sync.RWMutex
	stats    ProxyStats
	requests uint64
}

// ProxyStats tracks aggregate request metrics.
type ProxyStats struct {
	TotalRequests uint64         `json:"total_requests"`
	TotalBytesIn  uint64         `json:"total_bytes_in"`
	TotalBytesOut uint64         `json:"total_bytes_out"`
	StatusCodes   map[string]int `json:"status_codes"`
	AvgLatencyMs  float64        `json:"avg_latency_ms"`
	LastUpdated   time.Time      `json:"last_updated"`
}

var state = &ProxyState{
	stats: ProxyStats{
		StatusCodes: make(map[string]int),
	},
}

// recordStatus folds one completed request into the aggregate stats.
func recordStatus(status int, duration time.Duration) {
	state.mu.Lock()
	defer state.mu.Unlock()
	sc := fmt.Sprintf("%d", status)
	state.stats.StatusCodes[sc]++
	// Simple running average over completed requests.
	n := float64(state.stats.TotalRequests)
	if n < 1 {
		n = 1
	}
	state.stats.AvgLatencyMs += (float64(duration.Milliseconds()) - state.stats.AvgLatencyMs) / n
	state.stats.LastUpdated = time.Now()
}

// --- Lua API ---

// LuaAPI exposes request/response context to Lua scripts.
// Each field is populated per-request and accessible from within Lua via the `proxy` global.
type LuaAPI struct {
	Request        *http.Request     // Original HTTP request
	Response       *http.Response    // Response set by script (nil = proxy normally)
	Body           []byte            // Request body for inspection/modification
	Headers        map[string]string // All request headers (comma-joined multi-values)
	QueryArgs      map[string]string // URL query parameters
	Cancel         func()            // Cancel the script execution context
	Blocked        bool              // true if script called abort() or redirect() — short-circuit
	UpstreamURL    string            // The configured UPSTREAM value, available to scripts
	TrustProxyHdrs bool              // Whether X-Forwarded-* / X-Real-Ip may be trusted
	ReqHeaderSet   http.Header       // Request header mutations applied before forwarding
	ReqHeaderDel   map[string]bool   // Request headers removed by scripts
	PathOverride   string            // Upstream path override set via setPath ("" = unchanged)
	QueryOverrides map[string]string // Query params set via setQuery
}

// registerLuaAPI populates the Lua state with the `proxy` global table containing
// all functions and data available to scripts. Called once per request.
func registerLuaAPI(L *lua.LState, api *LuaAPI) {
	m := L.NewTable()

	// request info — read-only metadata about the incoming request
	reqTbl := L.NewTable()
	L.SetField(reqTbl, "method", lua.LString(api.Request.Method))
	L.SetField(reqTbl, "path", lua.LString(api.Request.URL.Path))
	L.SetField(reqTbl, "rawPath", lua.LString(api.Request.URL.EscapedPath()))
	L.SetField(reqTbl, "proto", lua.LString(api.Request.Proto))
	L.SetField(m, "request", reqTbl)

	// getHeader — look up a request header by name
	headersFn := L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		L.Push(lua.LString(api.Headers[http.CanonicalHeaderKey(key)]))
		return 1
	})
	L.SetField(m, "getHeader", headersFn)

	// getQuery — look up a URL query parameter by name
	queryFn := L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		L.Push(lua.LString(api.QueryArgs[key]))
		return 1
	})
	L.SetField(m, "getQuery", queryFn)

	// response.status — current response status (0 if not yet set)
	respTbl := L.NewTable()
	if api.Response != nil {
		L.SetField(respTbl, "status", lua.LNumber(api.Response.StatusCode))
	} else {
		L.SetField(respTbl, "status", lua.LNumber(0))
	}
	L.SetField(m, "response", respTbl)

	// setStatus — set the HTTP status code for the response
	respSetFn := L.NewFunction(func(L *lua.LState) int {
		status := L.CheckInt(1)
		api.Response = &http.Response{StatusCode: status}
		L.Push(lua.LTrue)
		return 1
	})
	L.SetField(m, "setStatus", respSetFn)

	// setResponseHeader — add a response header. If called multiple times,
	// headers accumulate in the same Header map.
	respHdrFn := L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		val := L.CheckString(2)
		if api.Response == nil {
			api.Response = &http.Response{}
		}
		if api.Response.Header == nil {
			api.Response.Header = http.Header{}
		}
		api.Response.Header.Set(key, val)
		L.Push(lua.LTrue)
		return 1
	})
	L.SetField(m, "setResponseHeader", respHdrFn)

	// --- Request mutation (applied before forwarding upstream) ---

	// setRequestHeader — replace a request header sent to the upstream
	setReqHdrFn := L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		val := L.CheckString(2)
		api.ReqHeaderSet.Set(key, val)
		delete(api.ReqHeaderDel, http.CanonicalHeaderKey(key))
		L.Push(lua.LTrue)
		return 1
	})
	L.SetField(m, "setRequestHeader", setReqHdrFn)

	// addRequestHeader — append a request header value
	addReqHdrFn := L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		val := L.CheckString(2)
		api.ReqHeaderSet.Add(key, val)
		delete(api.ReqHeaderDel, http.CanonicalHeaderKey(key))
		L.Push(lua.LTrue)
		return 1
	})
	L.SetField(m, "addRequestHeader", addReqHdrFn)

	// removeRequestHeader — drop a request header before forwarding
	delReqHdrFn := L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		api.ReqHeaderDel[http.CanonicalHeaderKey(key)] = true
		api.ReqHeaderSet.Del(key)
		L.Push(lua.LTrue)
		return 1
	})
	L.SetField(m, "removeRequestHeader", delReqHdrFn)

	// setPath — rewrite the path forwarded upstream
	setPathFn := L.NewFunction(func(L *lua.LState) int {
		p := L.CheckString(1)
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		api.PathOverride = p
		L.Push(lua.LTrue)
		return 1
	})
	L.SetField(m, "setPath", setPathFn)

	// setQuery — set a URL query parameter forwarded upstream
	setQueryFn := L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		val := L.CheckString(2)
		api.QueryOverrides[key] = val
		L.Push(lua.LTrue)
		return 1
	})
	L.SetField(m, "setQuery", setQueryFn)

	// getBody — return the full request body as a string
	bodyFn := L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(string(api.Body)))
		return 1
	})
	L.SetField(m, "getBody", bodyFn)

	// setBody — replace the request body before forwarding to upstream
	bodySetFn := L.NewFunction(func(L *lua.LState) int {
		api.Body = []byte(L.CheckString(1))
		L.Push(lua.LTrue)
		return 1
	})
	L.SetField(m, "setBody", bodySetFn)

	// redirect — short-circuit with an HTTP redirect response.
	// Usage: proxy.redirect(location) or proxy.redirect(location, statusCode)
	redirectFn := L.NewFunction(func(L *lua.LState) int {
		loc := L.CheckString(1)
		code := 302
		if L.GetTop() >= 2 && !LVIsNil(L, 2) {
			code = L.CheckInt(2)
		}
		api.Response = &http.Response{
			StatusCode: code,
			Header:     http.Header{"Location": []string{loc}},
		}
		api.Blocked = true
		L.Push(lua.LTrue)
		return 1
	})
	L.SetField(m, "redirect", redirectFn)

	// abort — short-circuit with an arbitrary status code and body.
	// Usage: proxy.abort(), proxy.abort(statusCode), proxy.abort(statusCode, body)
	// Default is 403 "blocked by script".
	abortFn := L.NewFunction(func(L *lua.LState) int {
		code := 403
		msg := "blocked by script"
		if L.GetTop() >= 1 && !LVIsNil(L, 1) {
			code = L.CheckInt(1)
		}
		if L.GetTop() >= 2 && !LVIsNil(L, 2) {
			msg = L.CheckString(2)
		}
		api.Response = &http.Response{
			StatusCode: code,
			Body:       io.NopCloser(bytes.NewReader([]byte(msg))),
		}
		api.Blocked = true
		if api.Cancel != nil {
			api.Cancel()
		}
		L.Push(lua.LTrue)
		return 1
	})
	L.SetField(m, "abort", abortFn)

	// log — print a message to the proxy's stderr log
	logFn := L.NewFunction(func(L *lua.LState) int {
		msg := L.CheckString(1)
		log.Printf("[lua] %s", msg)
		return 0
	})
	L.SetField(m, "log", logFn)

	// --- Network / connection info ---

	// clientIP — resolve the real client IP address.
	// Priority: X-Real-Ip → first entry of X-Forwarded-For → RemoteAddr (port stripped).
	// Forwarded headers are only consulted when TRUST_PROXY_HEADERS=true; otherwise a
	// client could forge its own source IP.
	clientIPFn := L.NewFunction(func(L *lua.LState) int {
		var ip string
		if api.TrustProxyHdrs {
			ip = api.Request.Header.Get("X-Real-Ip")
			if ip == "" {
				ip = api.Request.Header.Get("X-Forwarded-For")
				// X-Forwarded-For can be comma-separated; take first
				if idx := strings.Index(ip, ","); idx != -1 {
					ip = strings.TrimSpace(ip[:idx])
				}
			}
		}
		if ip == "" {
			ip = api.Request.RemoteAddr
			// Strip port if present
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}
		}
		L.Push(lua.LString(ip))
		return 1
	})
	L.SetField(m, "clientIP", clientIPFn)

	// remoteAddr — raw RemoteAddr of the direct peer (includes port)
	remoteAddrFn := L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(api.Request.RemoteAddr))
		return 1
	})
	L.SetField(m, "remoteAddr", remoteAddrFn)

	// scheme — "http" or "https". Respects X-Forwarded-Proto header (only when
	// trusted), falls back to checking TLS on the request.
	schemeFn := L.NewFunction(func(L *lua.LState) int {
		scheme := "http"
		if api.Request.TLS != nil {
			scheme = "https"
		}
		if api.TrustProxyHdrs {
			if xfp := api.Request.Header.Get("X-Forwarded-Proto"); xfp != "" {
				scheme = xfp
			}
		}
		L.Push(lua.LString(scheme))
		return 1
	})
	L.SetField(m, "scheme", schemeFn)

	// host — the Host header value from the request
	hostFn := L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(api.Request.Host))
		return 1
	})
	L.SetField(m, "host", hostFn)

	// upstreamURL — the configured UPSTREAM URL value
	upstreamURLFn := L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(api.UpstreamURL))
		return 1
	})
	L.SetField(m, "upstreamURL", upstreamURLFn)

	// jsonDecode — parse a JSON string into a Lua table.
	// Returns (table) on success, (nil, error_string) on failure.
	jsonDecodeFn := L.NewFunction(func(L *lua.LState) int {
		raw := L.CheckString(1)
		var out interface{}
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}
		L.Push(valueToLua(L, out))
		return 1
	})
	L.SetField(m, "jsonDecode", jsonDecodeFn)

	// jsonEncode — encode a Lua table into a JSON string.
	// Returns (json_string) on success, (nil, error_string) on failure.
	jsonEncodeFn := L.NewFunction(func(L *lua.LState) int {
		t := L.CheckTable(1)
		v := valueFromTable(L, t)
		data, err := json.Marshal(v)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}
		L.Push(lua.LString(data))
		return 1
	})
	L.SetField(m, "jsonEncode", jsonEncodeFn)

	L.SetGlobal("proxy", m)
}

// --- Date/time library for Lua ---

// registerDateLib installs an `os`-style date/time API into the Lua state.
// gopher-lua does not provide os.time/os.date by default (they live in the
// oslib sub-package), so we expose exactly what proxy rules need:
//
//	os.time()                  → epoch seconds (integer)
//	os.time(table)             → epoch seconds from a *t-style table
//	os.date("!*t") / os.date("*t") → table with year/month/day/... fields
//	os.date(fmt)               → strftime-formatted string (UTC with leading "!")
//	os.clock()                 → CPU seconds since process start
func registerDateLib(L *lua.LState) {
	o := L.NewTable()
	L.SetGlobal("os", o)

	timeFn := L.NewFunction(func(L *lua.LState) int {
		if L.GetTop() >= 1 && !LVIsNil(L, 1) {
			tbl := L.CheckTable(1)
			y := int(getNumField(L, tbl, "year", 1970))
			mon := int(getNumField(L, tbl, "month", 1))
			day := int(getNumField(L, tbl, "day", 1))
			h := int(getNumField(L, tbl, "hour", 0))
			mi := int(getNumField(L, tbl, "min", 0))
			s := int(getNumField(L, tbl, "sec", 0))
			ts := time.Date(y, time.Month(mon), day, h, mi, s, 0, time.UTC).Unix()
			L.Push(lua.LNumber(ts))
			return 1
		}
		L.Push(lua.LNumber(time.Now().Unix()))
		return 1
	})
	L.SetField(o, "time", timeFn)

	dateFn := L.NewFunction(func(L *lua.LState) int {
		fmtStr := "!*t"
		if L.GetTop() >= 1 && !LVIsNil(L, 1) {
			fmtStr = L.CheckString(1)
		}
		now := time.Now()
		if L.GetTop() >= 2 && !LVIsNil(L, 2) {
			now = time.Unix(int64(L.CheckNumber(2)), 0)
		}
		// "!" prefix forces UTC (Lua convention); without it we still use UTC so
		// proxy rules are deterministic regardless of server timezone.
		if strings.HasPrefix(fmtStr, "!") {
			fmtStr = strings.TrimPrefix(fmtStr, "!")
		}
		loc := time.UTC
		now = now.In(loc)
		if fmtStr == "*t" {
			tbl := L.NewTable()
			L.SetField(tbl, "year", lua.LNumber(now.Year()))
			L.SetField(tbl, "month", lua.LNumber(int(now.Month())))
			L.SetField(tbl, "day", lua.LNumber(now.Day()))
			L.SetField(tbl, "hour", lua.LNumber(now.Hour()))
			L.SetField(tbl, "min", lua.LNumber(now.Minute()))
			L.SetField(tbl, "sec", lua.LNumber(now.Second()))
			// Lua wday: 1=Sunday..7=Saturday; yday: 1..366
			L.SetField(tbl, "wday", lua.LNumber(int(now.Weekday())+1))
			L.SetField(tbl, "yday", lua.LNumber(now.YearDay()))
			L.SetField(tbl, "isdst", lua.LBool(false))
			L.Push(tbl)
			return 1
		}
		L.Push(lua.LString(strftime(now, fmtStr)))
		return 1
	})
	L.SetField(o, "date", dateFn)

	clockFn := L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(elapsedSinceProcessStart()))
		return 1
	})
	L.SetField(o, "clock", clockFn)
}

var processStart = time.Now()

func elapsedSinceProcessStart() float64 { return time.Since(processStart).Seconds() }

func getNumField(L *lua.LState, t *lua.LTable, name string, def lua.LNumber) lua.LNumber {
	v := L.GetField(t, name)
	if n, ok := v.(lua.LNumber); ok {
		return n
	}
	return def
}

// strftime implements the subset of C strftime used by common proxy rules.
// Supported: %Y %y %m %d %H %M %S %A %a %B %b %p %j %Z %z %e %I %R %T %D %F %c %x %X %%
func strftime(t time.Time, format string) string {
	var b strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 >= len(format) {
			b.WriteByte(format[i])
			continue
		}
		i++
		switch format[i] {
		case 'Y':
			b.WriteString(fmt.Sprintf("%04d", t.Year()))
		case 'y':
			b.WriteString(fmt.Sprintf("%02d", t.Year()%100))
		case 'm':
			b.WriteString(fmt.Sprintf("%02d", int(t.Month())))
		case 'd':
			b.WriteString(fmt.Sprintf("%02d", t.Day()))
		case 'e':
			b.WriteString(fmt.Sprintf("%2d", t.Day()))
		case 'H':
			b.WriteString(fmt.Sprintf("%02d", t.Hour()))
		case 'I':
			h := t.Hour() % 12
			if h == 0 {
				h = 12
			}
			b.WriteString(fmt.Sprintf("%02d", h))
		case 'M':
			b.WriteString(fmt.Sprintf("%02d", t.Minute()))
		case 'S':
			b.WriteString(fmt.Sprintf("%02d", t.Second()))
		case 'A':
			b.WriteString(t.Weekday().String())
		case 'a':
			b.WriteString(t.Weekday().String()[:3])
		case 'B':
			b.WriteString(t.Month().String())
		case 'b':
			b.WriteString(t.Month().String()[:3])
		case 'p':
			if t.Hour() < 12 {
				b.WriteString("AM")
			} else {
				b.WriteString("PM")
			}
		case 'j':
			b.WriteString(fmt.Sprintf("%03d", t.YearDay()))
		case 'R':
			b.WriteString(t.Format("15:04"))
		case 'T':
			b.WriteString(t.Format("15:04:05"))
		case 'D':
			b.WriteString(t.Format("01/02/06"))
		case 'F':
			b.WriteString(t.Format("2006-01-02"))
		case 'c':
			b.WriteString(t.Format(time.RFC1123))
		case 'x':
			b.WriteString(t.Format("01/02/06"))
		case 'X':
			b.WriteString(t.Format("15:04:05"))
		case 'Z':
			z, _ := t.Zone()
			b.WriteString(z)
		case 'z':
			_, off := t.Zone()
			sign := "+"
			if off < 0 {
				sign = "-"
				off = -off
			}
			b.WriteString(fmt.Sprintf("%s%02d%02d", sign, off/3600, (off%3600)/60))
		case '%':
			b.WriteByte('%')
		default:
			b.WriteByte('%')
			b.WriteByte(format[i])
		}
	}
	return b.String()
}

// --- Table <-> Go value helpers ---

// valueToLua converts a single Go value into an appropriate Lua LValue.
// Handles nested maps, slices, primitives, and nil (jsonDecode support).
func valueToLua(L *lua.LState, v interface{}) lua.LValue {
	switch vt := v.(type) {
	case map[string]interface{}:
		t := L.NewTable()
		for k, vv := range vt {
			L.SetField(t, k, valueToLua(L, vv))
		}
		return t
	case []interface{}:
		arr := L.NewTable()
		for i, item := range vt {
			arr.RawSetInt(i+1, valueToLua(L, item))
		}
		return arr
	case float64:
		return lua.LNumber(vt)
	case int:
		return lua.LNumber(vt)
	case int64:
		return lua.LNumber(vt)
	case bool:
		return lua.LBool(vt)
	case nil:
		return lua.LNil
	case string:
		return lua.LString(vt)
	default:
		return lua.LString(fmt.Sprintf("%v", v))
	}
}

// valueFromTable converts a Lua table back into a Go value for JSON encoding.
// Arrays (contiguous integer keys from 1) become []interface{}, everything
// else becomes map[string]interface{}.
func valueFromTable(L *lua.LState, t *lua.LTable) interface{} {
	if isArray(t) {
		arr := make([]interface{}, 0, t.Len())
		for i := 1; i <= t.Len(); i++ {
			arr = append(arr, luaValueToGo(L, t.RawGetInt(i)))
		}
		return arr
	}
	result := make(map[string]interface{})
	t.ForEach(func(k, v lua.LValue) {
		result[k.String()] = luaValueToGo(L, v)
	})
	return result
}

// isArray reports whether a table is a proper Lua array (sequential 1..n keys,
// no extra hash keys).
func isArray(t *lua.LTable) bool {
	n := t.Len()
	if n == 0 {
		// Empty table: ambiguous — treat as object (JSON {}).
		count := 0
		t.ForEach(func(_, _ lua.LValue) { count++ })
		return false
	}
	count := 0
	sequential := true
	t.ForEach(func(k, _ lua.LValue) {
		count++
		if kn, ok := k.(lua.LNumber); !ok || kn != lua.LNumber(count) {
			sequential = false
		}
	})
	return sequential && count == n
}

func luaValueToGo(L *lua.LState, v lua.LValue) interface{} {
	switch lv := v.(type) {
	case *lua.LTable:
		return valueFromTable(L, lv)
	case lua.LNumber:
		return float64(lv)
	case lua.LBool:
		return bool(lv)
	case lua.LString:
		return string(lv)
	default:
		if v == lua.LNil {
			return nil
		}
		return v.String()
	}
}

// --- Script runner ---

// ScriptRunner executes Lua scripts in isolated states. Each call creates a new
// Lua VM, registers the per-request API, and runs the script. Errors are returned
// so the caller can decide how to handle them.
type ScriptRunner struct{}

func NewScriptRunner() *ScriptRunner {
	return &ScriptRunner{}
}

func (sr *ScriptRunner) Run(script string, api *LuaAPI) error {
	L := lua.NewState()
	defer L.Close()

	registerDateLib(L)
	registerLuaAPI(L, api)

	if err := L.DoString(script); err != nil {
		return fmt.Errorf("lua error: %w", err)
	}
	return nil
}

// --- Handlers ---

// statsHandler serves aggregate request statistics as JSON at /__proxy_stats__.
func statsHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/__proxy_stats__" {
		http.NotFound(w, r)
		return
	}
	state.mu.RLock()
	s := state.stats
	state.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

// newProxy builds the reverse proxy for the given upstream. One instance per
// server; per-request behavior comes from the closure arguments.
func newProxy(upstream *url.URL) *httputil.ReverseProxy {
	p := &httputil.ReverseProxy{}
	p.FlushInterval = -1
	p.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.Canceled) {
			return // client went away; nobody left to answer
		}
		log.Printf("upstream error %s %s: %v", r.Method, r.URL.RequestURI(), err)
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, "bad gateway")
	}
	return p
}

// applyRequestMutations rewrites the outbound request according to the Lua
// script's mutations recorded on api.
func applyRequestMutations(out *http.Request, orig *http.Request, api *LuaAPI, upstream *url.URL) {
	out.URL.Scheme = upstream.Scheme
	out.URL.Host = upstream.Host
	out.URL.Path = orig.URL.Path
	out.URL.RawPath = orig.URL.EscapedPath()
	out.URL.RawQuery = orig.URL.RawQuery
	if api.PathOverride != "" {
		out.URL.Path = api.PathOverride
	}
	if len(api.QueryOverrides) > 0 {
		q := out.URL.Query()
		for k, v := range api.QueryOverrides {
			q.Set(k, v)
		}
		out.URL.RawQuery = q.Encode()
	}

	// Start from the original headers, minus hop-by-hop and forged forwarding
	// headers, then apply script mutations.
	out.Header = orig.Header.Clone()
	for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip"} {
		out.Header.Del(h)
	}
	for k := range api.ReqHeaderDel {
		out.Header.Del(k)
	}
	for k, vals := range api.ReqHeaderSet {
		for _, v := range vals {
			out.Header.Add(k, v)
		}
	}
	out.Host = upstream.Host
	out.RequestURI = ""
}

// --- Main ---

func run() error {
	cfg := loadConfig()

	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return fmt.Errorf("parse upstream %q: %w", cfg.Upstream, err)
	}
	if upstream.Scheme != "http" && upstream.Scheme != "https" {
		return fmt.Errorf("upstream %q: scheme must be http or https", cfg.Upstream)
	}
	if upstream.Host == "" {
		return fmt.Errorf("upstream %q: missing host", cfg.Upstream)
	}

	runner := NewScriptRunner()

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		ReadHeaderTimeout: 15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(os.Stderr, "http: ", log.LstdFlags),
	}

	mux := http.NewServeMux()

	// Main request handler: run Lua scripts, then proxy.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		state.mu.Lock()
		state.requests++
		state.stats.TotalRequests++
		state.mu.Unlock()

		// Build Lua API object for this request.
		api := &LuaAPI{
			Request:        r,
			Headers:        make(map[string]string),
			QueryArgs:      make(map[string]string),
			UpstreamURL:    cfg.Upstream,
			TrustProxyHdrs: cfg.TrustProxyHeaders,
			ReqHeaderSet:   http.Header{},
			ReqHeaderDel:   make(map[string]bool),
			QueryOverrides: make(map[string]string),
		}
		// Copy all request headers (multi-value joined with ", ")
		for k, vals := range r.Header {
			api.Headers[k] = strings.Join(vals, ", ")
		}
		// Copy all query parameters
		for k, vals := range r.URL.Query() {
			api.QueryArgs[k] = strings.Join(vals, ", ")
		}

		// Read body for Lua access (up to 10MB limit).
		// Replaced body reader so the proxy can still read it later.
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 10<<20))
			r.Body.Close()
		}
		api.Body = bodyBytes

		// Create a cancellable context for the script.
		_, cancel := context.WithCancel(context.Background())
		api.Cancel = cancel
		defer cancel()

		// Run all loaded Lua scripts sequentially against the same api object.
		// Scripts can modify the request, set response headers, or short-circuit.
		for path, src := range cfg.LuaScripts {
			err := runner.Run(src, api)
			if err != nil {
				log.Printf("lua script error (%s): %v", path, err)
				api.Response = &http.Response{
					StatusCode: 500,
					Body:       io.NopCloser(bytes.NewReader([]byte("script error"))),
				}
				api.Blocked = true
				break
			}
			// If script blocked (abort/redirect), stop running further scripts.
			if api.Blocked {
				break
			}
		}

		// If any script short-circuited (abort/redirect), send response directly.
		if api.Blocked && api.Response != nil {
			duration := time.Since(start)
			for k, vals := range api.Response.Header {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(api.Response.StatusCode)
			if api.Response.Body != nil {
				io.Copy(w, api.Response.Body)
			}
			recordStatus(api.Response.StatusCode, duration)
			log.Printf("%s %s %s %d %d %s", r.RemoteAddr, r.Method, r.URL.RequestURI(),
				api.Response.StatusCode, len(bodyBytes), duration)
			return
		}

		// Normal flow: restore body and forward to upstream.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		proxy := newProxy(upstream)

		// Rewrite the outgoing request: upstream target plus Lua mutations.
		orig := r.Clone(r.Context())
		proxy.Rewrite = func(out *httputil.ProxyRequest) {
			applyRequestMutations(out.Out, orig, api, upstream)
			out.SetXForwarded()
		}

		// After receiving the upstream response, merge any headers that Lua scripts
		// set via setResponseHeader(). This allows scripts to inject security headers,
		// logging info, etc. into proxied responses.
		upstreamStatus := 0
		proxy.ModifyResponse = func(resp *http.Response) error {
			upstreamStatus = resp.StatusCode
			if api.Response != nil && api.Response.Header != nil {
				for k, vals := range api.Response.Header {
					for _, v := range vals {
						resp.Header.Add(k, v)
					}
				}
			}
			return nil
		}

		proxy.ServeHTTP(w, r)
		duration := time.Since(start)
		status := upstreamStatus
		if status == 0 {
			status = http.StatusBadGateway // ErrorHandler path or transport failure
		}
		recordStatus(status, duration)
		log.Printf("%s %s %s %d %d %s", r.RemoteAddr, r.Method, r.URL.RequestURI(),
			status, len(bodyBytes), duration)
	})

	// Stats endpoint: GET /__proxy_stats__
	mux.HandleFunc("/__proxy_stats__", statsHandler)
	server.Handler = mux

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		log.Println("shutting down...")
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(sctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
		close(shutdownDone)
	}()

	log.Printf("listening on %s, proxying to %s", cfg.ListenAddr, cfg.Upstream)
	if len(cfg.LuaScripts) > 0 {
		log.Printf("loaded %d lua scripts", len(cfg.LuaScripts))
	}
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	<-shutdownDone
	log.Println("stopped")
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
