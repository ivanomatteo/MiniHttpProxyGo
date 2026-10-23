package httpcache

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// origin is a fake upstream: handler builds each response, calls counts them.
type origin struct {
	t       *testing.T
	calls   int
	last    *http.Request
	handler func(req *http.Request, call int) (status int, header http.Header, body string)
}

func (o *origin) RoundTrip(req *http.Request) (*http.Response, error) {
	o.calls++
	o.last = req
	status, header, body := o.handler(req, o.calls)
	// like a real transport, which canonicalizes the names ("ETag" -> "Etag")
	canonical := http.Header{}
	for name, values := range header {
		canonical[http.CanonicalHeaderKey(name)] = values
	}
	header = canonical
	return &http.Response{
		Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), StatusCode: status,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: header, Body: io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)), Request: req,
	}, nil
}

type testCache struct {
	*Cache
	t      *testing.T
	origin *origin
	clock  time.Time
}

func newTestCache(t *testing.T, maxBytes int64, handler func(*http.Request, int) (int, http.Header, string)) *testCache {
	tc := &testCache{Cache: New(maxBytes), t: t, origin: &origin{t: t, handler: handler}, clock: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	tc.now = func() time.Time { return tc.clock }
	return tc
}

func (tc *testCache) date() string { return tc.clock.Format(http.TimeFormat) }

// do sends a request through the cache and reads the whole body, as the
// reverse proxy does.
func (tc *testCache) do(method, rawURL string, header http.Header) (*http.Response, string, Status) {
	tc.t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		tc.t.Fatal(err)
	}
	if header != nil {
		req.Header = header
	}
	resp, status, err := tc.RoundTrip(req, tc.origin)
	if err != nil {
		tc.t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		tc.t.Fatal(err)
	}
	return resp, string(body), status
}

func (tc *testCache) expect(rawURL string, header http.Header, wantStatus Status, wantBody string) *http.Response {
	tc.t.Helper()
	resp, body, status := tc.do(http.MethodGet, rawURL, header)
	if status != wantStatus || body != wantBody {
		tc.t.Fatalf("GET %s = %s %q, want %s %q", rawURL, status, body, wantStatus, wantBody)
	}
	return resp
}

func TestFreshResponseIsServedFromCache(t *testing.T) {
	var tc *testCache
	tc = newTestCache(t, 1<<20, func(*http.Request, int) (int, http.Header, string) {
		return 200, http.Header{"Cache-Control": {"max-age=60"}, "Date": {tc.date()}}, "hello"
	})
	tc.expect("http://example.com/a", nil, Miss, "hello")
	tc.clock = tc.clock.Add(30 * time.Second)
	resp := tc.expect("http://example.com/a", nil, Hit, "hello")
	if age := resp.Header.Get("Age"); age != "30" {
		t.Errorf("Age = %q, want 30", age)
	}
	tc.clock = tc.clock.Add(31 * time.Second)
	tc.expect("http://example.com/a", nil, Miss, "hello")
	if tc.origin.calls != 2 {
		t.Errorf("origin calls = %d, want 2", tc.origin.calls)
	}
}

func TestStaleResponseIsRevalidated(t *testing.T) {
	var tc *testCache
	tc = newTestCache(t, 1<<20, func(req *http.Request, call int) (int, http.Header, string) {
		h := http.Header{"Cache-Control": {"max-age=10"}, "Date": {tc.date()}, "ETag": {`"v1"`}}
		if req.Header.Get("If-None-Match") == `"v1"` {
			h.Set("X-Refreshed", "yes")
			return 304, h, ""
		}
		return 200, h, "body"
	})
	tc.expect("http://example.com/a", nil, Miss, "body")
	tc.clock = tc.clock.Add(time.Minute)
	resp := tc.expect("http://example.com/a", nil, Revalidated, "body")
	if resp.StatusCode != 200 || resp.Header.Get("X-Refreshed") != "yes" {
		t.Errorf("revalidated response = %d %v, want 200 with the 304 headers", resp.StatusCode, resp.Header)
	}
	// The 304 made the entry fresh again.
	tc.expect("http://example.com/a", nil, Hit, "body")
}

func TestNotStoredResponses(t *testing.T) {
	cases := []struct {
		name   string
		header http.Header
		req    http.Header
		status int
	}{
		{"no-store", http.Header{"Cache-Control": {"no-store, max-age=60"}}, nil, 200},
		{"private", http.Header{"Cache-Control": {"private, max-age=60"}}, nil, 200},
		{"set-cookie", http.Header{"Cache-Control": {"max-age=60"}, "Set-Cookie": {"s=1"}}, nil, 200},
		{"vary star", http.Header{"Cache-Control": {"max-age=60"}, "Vary": {"*"}}, nil, 200},
		{"authorization", http.Header{"Cache-Control": {"max-age=60"}}, http.Header{"Authorization": {"Basic eDp5"}}, 200},
		{"request no-store", http.Header{"Cache-Control": {"max-age=60"}}, http.Header{"Cache-Control": {"no-store"}}, 200},
		{"no freshness nor validators", http.Header{}, nil, 200},
		{"uncacheable status", http.Header{"Cache-Control": {"max-age=60"}}, nil, 500},
		{"302 without explicit freshness", http.Header{"Last-Modified": {"Mon, 01 Jan 2024 00:00:00 GMT"}}, nil, 302},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := newTestCache(t, 1<<20, func(*http.Request, int) (int, http.Header, string) {
				return c.status, c.header.Clone(), "x"
			})
			tc.expect("http://example.com/a", c.req.Clone(), Miss, "x")
			tc.expect("http://example.com/a", c.req.Clone(), Miss, "x")
			if n := tc.Stats().Entries; n != 0 {
				t.Errorf("entries = %d, want 0", n)
			}
		})
	}
}

func TestAuthorizedResponseStoredWhenPublic(t *testing.T) {
	tc := newTestCache(t, 1<<20, func(*http.Request, int) (int, http.Header, string) {
		return 200, http.Header{"Cache-Control": {"public, max-age=60"}}, "x"
	})
	auth := http.Header{"Authorization": {"Basic eDp5"}}
	tc.expect("http://example.com/a", auth.Clone(), Miss, "x")
	tc.expect("http://example.com/a", auth.Clone(), Hit, "x")
}

func TestVaryKeepsSeparateVariants(t *testing.T) {
	tc := newTestCache(t, 1<<20, func(req *http.Request, _ int) (int, http.Header, string) {
		return 200, http.Header{"Cache-Control": {"max-age=60"}, "Vary": {"accept-encoding"}}, "enc=" + req.Header.Get("Accept-Encoding")
	})
	gzip := http.Header{"Accept-Encoding": {"gzip"}}
	tc.expect("http://example.com/a", gzip.Clone(), Miss, "enc=gzip")
	tc.expect("http://example.com/a", nil, Miss, "enc=")
	tc.expect("http://example.com/a", gzip.Clone(), Hit, "enc=gzip")
	tc.expect("http://example.com/a", nil, Hit, "enc=")
}

func TestRequestDirectives(t *testing.T) {
	var tc *testCache
	tc = newTestCache(t, 1<<20, func(*http.Request, int) (int, http.Header, string) {
		return 200, http.Header{"Cache-Control": {"max-age=60"}, "Date": {tc.date()}}, "x"
	})
	tc.expect("http://example.com/a", nil, Miss, "x")
	tc.clock = tc.clock.Add(20 * time.Second)
	tc.expect("http://example.com/a", http.Header{"Cache-Control": {"no-cache"}}, Miss, "x")
	tc.clock = tc.clock.Add(20 * time.Second)
	tc.expect("http://example.com/a", http.Header{"Pragma": {"no-cache"}}, Miss, "x")
	tc.clock = tc.clock.Add(20 * time.Second)
	tc.expect("http://example.com/a", http.Header{"Cache-Control": {"max-age=10"}}, Miss, "x")
	tc.clock = tc.clock.Add(50 * time.Second)
	tc.expect("http://example.com/a", http.Header{"Cache-Control": {"min-fresh=20"}}, Miss, "x")
	// stale by 30s: max-stale accepts it
	tc.clock = tc.clock.Add(90 * time.Second)
	tc.expect("http://example.com/a", http.Header{"Cache-Control": {"max-stale=60"}}, Hit, "x")
	tc.expect("http://example.com/a", http.Header{"Cache-Control": {"max-stale=10"}}, Miss, "x")

	resp, _, status := tc.do(http.MethodGet, "http://example.com/missing", http.Header{"Cache-Control": {"only-if-cached"}})
	if resp.StatusCode != http.StatusGatewayTimeout || status != Miss {
		t.Errorf("only-if-cached on a miss = %d %s, want 504", resp.StatusCode, status)
	}
}

func TestMustRevalidateIsNeverServedStale(t *testing.T) {
	var tc *testCache
	tc = newTestCache(t, 1<<20, func(*http.Request, int) (int, http.Header, string) {
		return 200, http.Header{"Cache-Control": {"max-age=10, must-revalidate"}, "Date": {tc.date()}}, "x"
	})
	tc.expect("http://example.com/a", nil, Miss, "x")
	tc.clock = tc.clock.Add(time.Minute)
	tc.expect("http://example.com/a", http.Header{"Cache-Control": {"max-stale"}}, Miss, "x")
}

func TestClientConditionalAnsweredFromCache(t *testing.T) {
	tc := newTestCache(t, 1<<20, func(*http.Request, int) (int, http.Header, string) {
		return 200, http.Header{"Cache-Control": {"max-age=60"}, "ETag": {`W/"abc"`}}, "x"
	})
	tc.expect("http://example.com/a", nil, Miss, "x")
	resp := tc.expect("http://example.com/a", http.Header{"If-None-Match": {`"other", "abc"`}}, Hit, "")
	if resp.StatusCode != http.StatusNotModified || resp.Header.Get("ETag") != `W/"abc"` {
		t.Errorf("conditional hit = %d %v, want 304 with ETag", resp.StatusCode, resp.Header)
	}
	resp = tc.expect("http://example.com/a", http.Header{"If-None-Match": {`"other"`}}, Hit, "x")
	if resp.StatusCode != 200 {
		t.Errorf("non-matching conditional = %d, want 200", resp.StatusCode)
	}
}

func TestHeuristicAndExpiresFreshness(t *testing.T) {
	var tc *testCache
	tc = newTestCache(t, 1<<20, func(req *http.Request, _ int) (int, http.Header, string) {
		switch req.URL.Path {
		case "/heuristic": // modified 10 hours ago: fresh for 1 hour
			return 200, http.Header{"Date": {tc.date()}, "Last-Modified": {tc.clock.Add(-10 * time.Hour).Format(http.TimeFormat)}}, "h"
		case "/expires":
			return 200, http.Header{"Date": {tc.date()}, "Expires": {tc.clock.Add(time.Hour).Format(http.TimeFormat)}}, "e"
		default: // invalid Expires: stale at once
			return 200, http.Header{"Date": {tc.date()}, "Expires": {"0"}}, "i"
		}
	})
	for _, path := range []string{"/heuristic", "/expires", "/invalid"} {
		tc.do(http.MethodGet, "http://example.com"+path, nil)
	}
	tc.clock = tc.clock.Add(59 * time.Minute)
	tc.expect("http://example.com/heuristic", nil, Hit, "h")
	tc.expect("http://example.com/expires", nil, Hit, "e")
	tc.expect("http://example.com/invalid", nil, Miss, "i")
	tc.clock = tc.clock.Add(2 * time.Minute)
	tc.expect("http://example.com/heuristic", nil, Miss, "h")
	tc.expect("http://example.com/expires", nil, Miss, "e")
}

func TestUnsafeMethodInvalidates(t *testing.T) {
	tc := newTestCache(t, 1<<20, func(req *http.Request, _ int) (int, http.Header, string) {
		if req.Method == http.MethodPost {
			return 201, http.Header{"Location": {"/b"}}, ""
		}
		return 200, http.Header{"Cache-Control": {"max-age=60"}}, req.URL.Path
	})
	tc.expect("http://example.com/a", nil, Miss, "/a")
	tc.expect("http://example.com/b", nil, Miss, "/b")
	if _, _, status := tc.do(http.MethodPost, "http://example.com/a", nil); status != Bypass {
		t.Fatalf("POST status = %s, want BYPASS", status)
	}
	tc.expect("http://example.com/a", nil, Miss, "/a")
	tc.expect("http://example.com/b", nil, Miss, "/b")
}

func TestBypassedRequests(t *testing.T) {
	tc := newTestCache(t, 1<<20, func(*http.Request, int) (int, http.Header, string) {
		return 200, http.Header{"Cache-Control": {"max-age=60"}}, "x"
	})
	tc.expect("http://example.com/a", http.Header{"Range": {"bytes=0-1"}}, Bypass, "x")
	if _, _, status := tc.do(http.MethodHead, "http://example.com/a", nil); status != Bypass {
		t.Errorf("HEAD status = %s, want BYPASS", status)
	}
	if n := tc.Stats().Entries; n != 0 {
		t.Errorf("entries = %d, want 0", n)
	}
}

func TestIncompleteOrLargeBodiesAreNotStored(t *testing.T) {
	big := strings.Repeat("x", 10_000)
	tc := newTestCache(t, 64_000, func(req *http.Request, _ int) (int, http.Header, string) {
		return 200, http.Header{"Cache-Control": {"max-age=60"}}, big
	})
	// larger than maxBytes/8
	tc.expect("http://example.com/big", nil, Miss, big)
	tc.expect("http://example.com/big", nil, Miss, big)

	tc.maxObject = 1 << 20
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/partial", nil)
	resp, _, err := tc.RoundTrip(req, tc.origin)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadFull(resp.Body, make([]byte, 100))
	resp.Body.Close() // client went away
	if n := tc.Stats().Entries; n != 0 {
		t.Errorf("entries = %d, want 0 after an incomplete body", n)
	}
}

func TestGDSFEvictionKeepsPopularEntries(t *testing.T) {
	body := strings.Repeat("x", 1000)
	tc := newTestCache(t, 8*1600, func(*http.Request, int) (int, http.Header, string) {
		return 200, http.Header{"Cache-Control": {"max-age=600"}}, body
	})
	tc.expect("http://example.com/popular", nil, Miss, body)
	for range 5 {
		tc.expect("http://example.com/popular", nil, Hit, body)
	}
	// A scan of one-time URLs, filling the cache a few times over, does not
	// push out the popular entry.
	for i := range 20 {
		tc.do(http.MethodGet, fmt.Sprintf("http://example.com/once/%d", i), nil)
		if s := tc.Stats(); s.Bytes > s.MaxBytes {
			t.Fatalf("cache uses %d bytes, over its %d limit", s.Bytes, s.MaxBytes)
		}
	}
	tc.expect("http://example.com/popular", nil, Hit, body)
	if s := tc.Stats(); s.Evictions == 0 {
		t.Errorf("evictions = 0, want the scan to evict entries")
	}
	// The popularity of an unused entry decays: enough new popular entries
	// eventually push it out.
	for i := range 200 {
		u := fmt.Sprintf("http://example.com/new/%d", i)
		for range 8 {
			tc.do(http.MethodGet, u, nil)
		}
	}
	tc.expect("http://example.com/popular", nil, Miss, body)
}

func TestVaryChangeDropsOldVariants(t *testing.T) {
	tc := newTestCache(t, 1<<20, func(_ *http.Request, call int) (int, http.Header, string) {
		h := http.Header{"Cache-Control": {"max-age=60"}, "Vary": {"Accept-Language"}}
		if call > 1 {
			h.Set("Vary", "Accept-Encoding")
		}
		return 200, h, "x"
	})
	tc.expect("http://example.com/a", http.Header{"Accept-Language": {"it"}}, Miss, "x")
	tc.expect("http://example.com/a", http.Header{"Accept-Language": {"en"}}, Miss, "x")
	// The response now varies only on Accept-Encoding: the stored one fits.
	tc.expect("http://example.com/a", http.Header{"Accept-Language": {"it"}}, Hit, "x")
	if n := tc.Stats().Entries; n != 1 {
		t.Errorf("entries = %d, want 1 (old variants dropped)", n)
	}
}

func TestSplitListKeepsQuotedCommas(t *testing.T) {
	got := splitList(`no-cache="Set-Cookie, X-Foo", max-age=5, "a,b"`)
	want := []string{`no-cache="Set-Cookie, X-Foo"`, "max-age=5", `"a,b"`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("splitList = %q, want %q", got, want)
	}
}
