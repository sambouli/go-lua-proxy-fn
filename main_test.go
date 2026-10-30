package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// --- helpers ---

// newTestAPI builds a LuaAPI for a synthetic request without going through HTTP.
func newTestAPI(t *testing.T, method, target string, body string, hdrs map[string]string, trust bool) *LuaAPI {
	t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	api := &LuaAPI{
		Request:        r,
		Headers:        make(map[string]string),
		QueryArgs:      make(map[string]string),
		UpstreamURL:    "http://upstream.test:9999",
		TrustProxyHdrs: trust,
		ReqHeaderSet:   http.Header{},
		ReqHeaderDel:   make(map[string]bool),
		QueryOverrides: make(map[string]string),
	}
	for k, vals := range r.Header {
		api.Headers[k] = strings.Join(vals, ", ")
	}
	for k, vals := range r.URL.Query() {
		api.QueryArgs[k] = strings.Join(vals, ", ")
	}
	api.Body = []byte(body)
	return api
}

// runLua runs script against api in a fresh state, mirroring ScriptRunner.Run.
func runLua(t *testing.T, script string, api *LuaAPI) error {
	t.Helper()
	sr := NewScriptRunner()
	return sr.Run(script, api)
}

// mustRunLua fails the test if the script errors.
func mustRunLua(t *testing.T, script string, api *LuaAPI) {
	t.Helper()
	if err := runLua(t, script, api); err != nil {
		t.Fatalf("lua script failed: %v\nscript:\n%s", err, script)
	}
}

// --- Config tests ---

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("LISTEN_ADDR", "")
	t.Setenv("UPSTREAM", "")
	t.Setenv("LUA_SCRIPTS", "")
	t.Setenv("TRUST_PROXY_HEADERS", "")
	cfg := loadConfig()
	if cfg.ListenAddr != ":8080" {
		t.Errorf("expected :8080, got %s", cfg.ListenAddr)
	}
	if cfg.Upstream != "http://localhost:9090" {
		t.Errorf("expected http://localhost:9090, got %s", cfg.Upstream)
	}
	if cfg.ScriptTimeout != 5*time.Second {
		t.Errorf("expected 5s, got %v", cfg.ScriptTimeout)
	}
	if cfg.TrustProxyHeaders {
		t.Error("TrustProxyHeaders should default to false")
	}
}

func TestLoadConfigTrustProxyHeaders(t *testing.T) {
	t.Setenv("TRUST_PROXY_HEADERS", "true")
	cfg := loadConfig()
	if !cfg.TrustProxyHeaders {
		t.Error("TrustProxyHeaders should be true when TRUST_PROXY_HEADERS=true")
	}
	t.Setenv("TRUST_PROXY_HEADERS", "TRUE")
	cfg = loadConfig()
	if !cfg.TrustProxyHeaders {
		t.Error("TrustProxyHeaders should accept TRUE case-insensitively")
	}
	t.Setenv("TRUST_PROXY_HEADERS", "yes")
	cfg = loadConfig()
	if cfg.TrustProxyHeaders {
		t.Error("TrustProxyHeaders should stay false for unrecognized value")
	}
}

func TestGetEnv(t *testing.T) {
	t.Setenv("GLP_TEST_VAR", "hello")
	if v := getEnv("GLP_TEST_VAR", "fallback"); v != "hello" {
		t.Errorf("expected hello, got %s", v)
	}
	t.Setenv("GLP_TEST_VAR", "")
	if v := getEnv("GLP_TEST_VAR", "fallback"); v != "fallback" {
		t.Errorf("expected fallback, got %s", v)
	}
}

// --- clientIP tests ---

func TestClientIPUntrustedIgnoresForwardedHeaders(t *testing.T) {
	// Without trust, a forged X-Forwarded-For must NOT become the client IP.
	api := newTestAPI(t, "GET", "/", "", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
		"X-Real-Ip":       "5.6.7.8",
	}, false)
	L := lua.NewState()
	defer L.Close()
	registerDateLib(L)
	registerLuaAPI(L, api)
	L.DoString(`_G.result = proxy.clientIP()`)
	got := L.GetGlobal("result").String()
	// httptest sets RemoteAddr to 192.0.2.1:1234
	if got != "192.0.2.1" {
		t.Errorf("untrusted clientIP: expected 192.0.2.1, got %q", got)
	}
}

func TestClientIPTrustedPrefersRealIP(t *testing.T) {
	api := newTestAPI(t, "GET", "/", "", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
		"X-Real-Ip":       "5.6.7.8",
	}, true)
	L := lua.NewState()
	defer L.Close()
	registerDateLib(L)
	registerLuaAPI(L, api)
	L.DoString(`_G.result = proxy.clientIP()`)
	if got := L.GetGlobal("result").String(); got != "5.6.7.8" {
		t.Errorf("expected 5.6.7.8 (X-Real-Ip wins), got %q", got)
	}
}

func TestClientIPTrustedFallsToXFFFirstEntry(t *testing.T) {
	api := newTestAPI(t, "GET", "/", "", map[string]string{
		"X-Forwarded-For": "9.9.9.9 , 8.8.8.8",
	}, true)
	L := lua.NewState()
	defer L.Close()
	registerDateLib(L)
	registerLuaAPI(L, api)
	L.DoString(`_G.result = proxy.clientIP()`)
	if got := L.GetGlobal("result").String(); got != "9.9.9.9" {
		t.Errorf("expected 9.9.9.9 (first XFF entry, trimmed), got %q", got)
	}
}

func TestClientIPNoPortInResult(t *testing.T) {
	api := newTestAPI(t, "GET", "/", "", nil, false)
	if strings.Contains(api.Request.RemoteAddr, ":") {
		// sanity: httptest gives host:port
		L := lua.NewState()
		defer L.Close()
		registerDateLib(L)
		registerLuaAPI(L, api)
		L.DoString(`_G.result = proxy.clientIP()`)
		if got := L.GetGlobal("result").String(); strings.Contains(got, ":") {
			t.Errorf("clientIP should strip port, got %q", got)
		}
	}
}

// --- header rewrite tests ---

func TestRequestHeaderMutations(t *testing.T) {
	api := newTestAPI(t, "GET", "/x?a=1", "", map[string]string{"X-Drop": "bye"}, false)
	mustRunLua(t, `
		proxy.setRequestHeader("X-Added", "one")
		proxy.addRequestHeader("X-Multi", "a")
		proxy.addRequestHeader("X-Multi", "b")
		proxy.removeRequestHeader("X-Drop")
	`, api)

	up, _ := url.Parse("http://backend.test")
	out, _ := http.NewRequest("GET", "http://x/", nil)
	applyRequestMutations(out, api.Request, api, up)

	if got := out.Header.Get("X-Added"); got != "one" {
		t.Errorf("X-Added upstream: expected one, got %q", got)
	}
	if mv := out.Header.Values("X-Multi"); len(mv) != 2 || mv[0] != "a" || mv[1] != "b" {
		t.Errorf("X-Multi upstream: expected [a b], got %v", mv)
	}
	if got := out.Header.Get("X-Drop"); got != "" {
		t.Errorf("X-Drop should be removed, got %q", got)
	}
}

// --- path / query override tests ---

func TestPathAndQueryOverrides(t *testing.T) {
	api := newTestAPI(t, "GET", "/original?keep=1&change=old", "", nil, false)
	mustRunLua(t, `
		proxy.setPath("/rewritten")
		proxy.setQuery("change", "new")
	`, api)
	if api.PathOverride != "/rewritten" {
		t.Errorf("PathOverride: %q", api.PathOverride)
	}
	if api.QueryOverrides["change"] != "new" {
		t.Errorf("QueryOverrides change: %v", api.QueryOverrides)
	}
}

func TestApplyRequestMutations(t *testing.T) {
	up, _ := url.Parse("http://backend.test:8080")
	api := newTestAPI(t, "GET", "/orig?keep=1", "", map[string]string{
		"X-Forwarded-For": "6.6.6.6",
		"X-Drop":          "gone",
	}, false)
	api.ReqHeaderSet.Set("X-Add", "yes")
	api.ReqHeaderDel["X-Drop"] = true
	api.PathOverride = "/new"
	api.QueryOverrides["z"] = "9"

	out, _ := http.NewRequest("GET", "http://x/", nil)
	applyRequestMutations(out, api.Request, api, up)

	if out.URL.String() != "http://backend.test:8080/new?keep=1&z=9" {
		t.Errorf("out URL: %s", out.URL.String())
	}
	if out.Header.Get("X-Forwarded-For") != "" {
		t.Error("inbound XFF must be stripped before SetXForwarded")
	}
	if out.Header.Get("X-Drop") != "" {
		t.Error("X-Drop should be deleted")
	}
	if out.Header.Get("X-Add") != "yes" {
		t.Error("X-Add should be set")
	}
	if out.Host != "backend.test:8080" {
		t.Errorf("Host: %s", out.Host)
	}
}

// --- response manipulation tests ---

func TestSetResponseHeaderMerges(t *testing.T) {
	api := newTestAPI(t, "GET", "/", "", nil, false)
	mustRunLua(t, `
		proxy.setResponseHeader("X-One", "1")
		proxy.setResponseHeader("X-Two", "2")
	`, api)
	if api.Response == nil || api.Blocked {
		t.Fatal("setResponseHeader must not block")
	}
	if api.Response.Header.Get("X-One") != "1" || api.Response.Header.Get("X-Two") != "2" {
		t.Errorf("headers: %v", api.Response.Header)
	}
}

func TestAbortShortCircuits(t *testing.T) {
	api := newTestAPI(t, "GET", "/", "", nil, false)
	mustRunLua(t, `proxy.abort(418, "teapot")`, api)
	if !api.Blocked || api.Response.StatusCode != 418 {
		t.Fatalf("blocked=%v status=%d", api.Blocked, api.Response.StatusCode)
	}
	body, _ := io.ReadAll(api.Response.Body)
	if string(body) != "teapot" {
		t.Errorf("body: %q", body)
	}
}

func TestRedirectShortCircuits(t *testing.T) {
	api := newTestAPI(t, "GET", "/", "", nil, false)
	mustRunLua(t, `proxy.redirect("/login")`, api)
	if !api.Blocked || api.Response.StatusCode != 302 {
		t.Fatalf("blocked=%v status=%d", api.Blocked, api.Response.StatusCode)
	}
	if api.Response.Header.Get("Location") != "/login" {
		t.Errorf("Location: %v", api.Response.Header)
	}
}

func TestBodyGetSet(t *testing.T) {
	api := newTestAPI(t, "POST", "/", "original", nil, false)
	mustRunLua(t, `
		local b = proxy.getBody()
		proxy.setBody(b .. "-mutated")
	`, api)
	if string(api.Body) != "original-mutated" {
		t.Errorf("body: %q", api.Body)
	}
}

// --- JSON round-trip ---

func TestJSONRoundTrip(t *testing.T) {
	api := newTestAPI(t, "GET", "/", "", nil, false)
	mustRunLua(t, `
		local t = proxy.jsonDecode('{"a":1,"b":"two","c":[3,4],"d":{"e":true},"f":null}')
		assert(t.a == 1, "a")
		assert(t.b == "two", "b")
		assert(t.c[1] == 3 and t.c[2] == 4, "c")
		assert(t.d.e == true, "d.e")
		assert(t.f == nil, "f")
		local s = proxy.jsonEncode({x = 1.5, y = "z"})
		local back = proxy.jsonDecode(s)
		assert(back.x == 1.5 and back.y == "z", "roundtrip")
		-- arrays encode as arrays
		local arr = proxy.jsonEncode(proxy.jsonDecode('[7,8]'))
		assert(arr == "[7,8]", "array json: " .. arr)
	`, api)
}

func TestJSONDecodeError(t *testing.T) {
	api := newTestAPI(t, "GET", "/", "", nil, false)
	mustRunLua(t, `
		local t, err = proxy.jsonDecode("{not json")
		assert(t == nil, "t should be nil")
		assert(type(err) == "string" and #err > 0, "err string")
	`, api)
}

// --- os.date / os.time ---

func TestOsTimeEpoch(t *testing.T) {
	api := newTestAPI(t, "GET", "/", "", nil, false)
	before := time.Now().Unix()
	mustRunLua(t, `
		local t = os.time()
		assert(t == math.floor(t), "epoch integer")
		assert(t > 1700000000, "plausible epoch: " .. tostring(t))
	`, api)
	after := time.Now().Unix()
	if after < before {
		t.Fatal("clock went backwards")
	}
}

func TestOsDateDayOfWeek(t *testing.T) {
	api := newTestAPI(t, "GET", "/", "", nil, false)
	// Fixed epoch: 2026-10-30 was a Friday (UTC).
	mustRunLua(t, `
		local d = os.date("!%A", 1793318400)  -- 2026-10-30T00:00:00Z
		assert(d == "Friday", "got " .. d)
		local s = os.date("!%a", 1793318400)
		assert(s == "Fri", "short: " .. s)
		local tbl = os.date("*t", 1793318400)
		assert(tbl.year == 2026, "year " .. tbl.year)
		assert(tbl.month == 10, "month " .. tbl.month)
		assert(tbl.day == 30, "day " .. tbl.day)
		assert(tbl.wday == 6, "wday (1=Sun..7=Sat): " .. tbl.wday)
	`, api)
}

func TestOsDateTodayMatchesGo(t *testing.T) {
	api := newTestAPI(t, "GET", "/", "", nil, false)
	want := time.Now().UTC().Weekday().String()
	script := fmt.Sprintf(`
		local d = os.date("!%%A")
		assert(d == %q, "expected " .. %q .. " got " .. d)
	`, want, want)
	mustRunLua(t, script, api)
}

func TestOsTimeFromTable(t *testing.T) {
	api := newTestAPI(t, "GET", "/", "", nil, false)
	mustRunLua(t, `
		local ts = os.time({year=2026, month=10, day=30, hour=0, min=0, sec=0})
		assert(ts == 1793318400, "ts=" .. ts)
	`, api)
}

// --- strftime unit tests ---

func TestStrftime(t *testing.T) {
	ts := time.Date(2026, 10, 30, 13, 5, 9, 0, time.UTC) // Friday
	cases := map[string]string{
		"%Y-%m-%d": "2026-10-30",
		"%A":       "Friday",
		"%a":       "Fri",
		"%B":       "October",
		"%b":       "Oct",
		"%H:%M:%S": "13:05:09",
		"%I %p":    "01 PM",
		"%j":       "303",
		"100%%":    "100%",
	}
	for f, want := range cases {
		if got := strftime(ts, f); got != want {
			t.Errorf("strftime(%q) = %q, want %q", f, got, want)
		}
	}
}

// --- script error handling ---

func TestScriptSyntaxErrorSurfaces(t *testing.T) {
	api := newTestAPI(t, "GET", "/", "", nil, false)
	err := runLua(t, `this is not lua(((`, api)
	if err == nil || !strings.Contains(err.Error(), "lua error") {
		t.Errorf("expected lua error, got %v", err)
	}
}

// --- stats ---

func TestRecordStatus(t *testing.T) {
	state.mu.Lock()
	state.stats = ProxyStats{StatusCodes: make(map[string]int)}
	state.mu.Unlock()

	recordStatus(200, 5*time.Millisecond)
	recordStatus(200, 15*time.Millisecond)
	recordStatus(502, 10*time.Millisecond)

	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.stats.StatusCodes["200"] != 2 || state.stats.StatusCodes["502"] != 1 {
		t.Errorf("status codes: %v", state.stats.StatusCodes)
	}
	if state.stats.AvgLatencyMs <= 0 {
		t.Errorf("avg latency: %v", state.stats.AvgLatencyMs)
	}
}

func TestStatsHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/__proxy_stats__", nil)
	rec := httptest.NewRecorder()
	statsHandler(rec, req)
	if rec.Code != 200 {
		t.Fatalf("stats code: %d", rec.Code)
	}
	var s ProxyStats
	if err := json.NewDecoder(rec.Body).Decode(&s); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	// wrong path → 404
	rec2 := httptest.NewRecorder()
	statsHandler(rec2, httptest.NewRequest("GET", "/other", nil))
	if rec2.Code != 404 {
		t.Errorf("wrong path should 404, got %d", rec2.Code)
	}
}

// --- end-to-end: full handler with dummy upstream ---

// buildHandlerForTest wires the same pipeline as run()'s mux handler so the
// e2e tests exercise the real code path (scripts → mutate → proxy → merge).
func buildHandlerForTest(t *testing.T, upstreamURL string, scripts map[string]string, trust bool) http.Handler {
	t.Helper()
	up, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	runner := NewScriptRunner()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		api := &LuaAPI{
			Request:        r,
			Headers:        make(map[string]string),
			QueryArgs:      make(map[string]string),
			UpstreamURL:    upstreamURL,
			TrustProxyHdrs: trust,
			ReqHeaderSet:   http.Header{},
			ReqHeaderDel:   make(map[string]bool),
			QueryOverrides: make(map[string]string),
		}
		for k, vals := range r.Header {
			api.Headers[k] = strings.Join(vals, ", ")
		}
		for k, vals := range r.URL.Query() {
			api.QueryArgs[k] = strings.Join(vals, ", ")
		}
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 10<<20))
			r.Body.Close()
		}
		api.Body = bodyBytes

		for _, src := range scripts {
			if err := runner.Run(src, api); err != nil {
				http.Error(w, "script error", 500)
				return
			}
			if api.Blocked {
				break
			}
		}
		if api.Blocked && api.Response != nil {
			for k, vals := range api.Response.Header {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(api.Response.StatusCode)
			if api.Response.Body != nil {
				io.Copy(w, api.Response.Body)
			}
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		proxy := newProxy(up)
		orig := r.Clone(r.Context())
		proxy.Rewrite = func(out *httputil.ProxyRequest) {
			applyRequestMutations(out.Out, orig, api, up)
			out.SetXForwarded()
		}
		proxy.ModifyResponse = func(resp *http.Response) error {
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
		_ = start
	})
	return mux
}

// TestEndToEndClientIPAndDayOfWeek is the headline scenario:
// dummy web server + reverse proxy + Lua rule that fetches the client IP and
// echoes it in a response header, plus the day of the week in another header.
func TestEndToEndClientIPAndDayOfWeek(t *testing.T) {
	// Dummy upstream: echoes what it received as JSON.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "yes")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"path":           r.URL.Path,
			"xff":            r.Header.Get("X-Forwarded-For"),
			"x-added-by-lua": r.Header.Get("X-Added-By-Lua"),
		})
	}))
	defer upstream.Close()

	scripts := map[string]string{"rule.lua": `
		local ip = proxy.clientIP()
		proxy.setResponseHeader("X-Client-IP", ip)
		proxy.setResponseHeader("X-Day-Of-Week", os.date("!%A"))
		proxy.setRequestHeader("X-Added-By-Lua", "1")
	`}

	proxySrv := httptest.NewServer(buildHandlerForTest(t, upstream.URL, scripts, false))
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	// 1. Client IP header must match the socket peer (httptest client is 127.0.0.1).
	gotIP := resp.Header.Get("X-Client-IP")
	if gotIP != "127.0.0.1" {
		t.Errorf("X-Client-IP: expected 127.0.0.1, got %q", gotIP)
	}

	// 2. Day-of-week header must match today's UTC weekday.
	wantDOW := time.Now().UTC().Weekday().String()
	gotDOW := resp.Header.Get("X-Day-Of-Week")
	if gotDOW != wantDOW {
		t.Errorf("X-Day-Of-Week: expected %s, got %s", wantDOW, gotDOW)
	}

	// 3. Upstream actually served the content and saw the Lua-set request header.
	var echo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("decode echo: %v", err)
	}
	if echo["path"] != "/hello" {
		t.Errorf("upstream path: %v", echo["path"])
	}
	if echo["x-added-by-lua"] != "1" {
		t.Errorf("upstream did not see Lua request header: %v", echo)
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Error("upstream response headers must pass through")
	}
	// 4. SetXForwarded added XFF for the upstream (trust setting governs Lua-side reads only).
	if echo["xff"] == "" || echo["xff"] == "<nil>" {
		t.Errorf("upstream should see X-Forwarded-For set by proxy, got %v", echo["xff"])
	}
}

// TestEndToEndForgedClientIPIgnored proves the trust gate end to end.
func TestEndToEndForgedClientIPIgnored(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer upstream.Close()

	scripts := map[string]string{"r.lua": `
		proxy.setResponseHeader("X-Client-IP", proxy.clientIP())
	`}
	proxySrv := httptest.NewServer(buildHandlerForTest(t, upstream.URL, scripts, false))
	defer proxySrv.Close()

	req, _ := http.NewRequest("GET", proxySrv.URL+"/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-Ip", "5.6.7.8")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("X-Client-IP"); got != "127.0.0.1" {
		t.Errorf("forged XFF/X-Real-Ip must be ignored untrusted: got %q", got)
	}
}

// TestEndToEndAbort verifies short-circuit responses never reach upstream.
func TestEndToEndAbort(t *testing.T) {
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	scripts := map[string]string{"block.lua": `
		if proxy.request.path == "/secret" then
			proxy.abort(403, "nope")
		end
	`}
	proxySrv := httptest.NewServer(buildHandlerForTest(t, upstream.URL, scripts, false))
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/secret")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 || string(body) != "nope" {
		t.Errorf("abort: %d %q", resp.StatusCode, body)
	}
	if reached {
		t.Error("aborted request must not reach upstream")
	}
}
