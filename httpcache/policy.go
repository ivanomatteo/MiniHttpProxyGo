package httpcache

import (
	"net/http"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// heuristicFraction and heuristicMax bound the freshness given to a
	// response with Last-Modified and no explicit expiration (RFC 9111 4.2.2).
	heuristicFraction = 10
	heuristicMax      = 24 * time.Hour
)

// cacheControl holds the directives of the Cache-Control header, lower-cased,
// with their unquoted argument ("" when there is none).
type cacheControl map[string]string

func parseCacheControl(h http.Header) cacheControl {
	cc := cacheControl{}
	for _, line := range h.Values("Cache-Control") {
		for _, part := range splitList(line) {
			name, value, _ := strings.Cut(part, "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			cc[name] = strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return cc
}

func (cc cacheControl) has(name string) bool {
	_, ok := cc[name]
	return ok
}

// seconds returns the delta-seconds argument of a directive. An invalid
// argument counts as 0, the safest value for max-age and s-maxage.
func (cc cacheControl) seconds(name string) (time.Duration, bool) {
	value, ok := cc[name]
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 0 {
		return 0, true
	}
	// clamp to avoid overflow, as RFC 9111 1.2.2 allows
	return time.Duration(min(n, 1<<31)) * time.Second, true
}

// requestDirectives are the parts of a request that affect the cache.
type requestDirectives struct {
	noCache      bool
	noStore      bool
	onlyIfCached bool
	maxAge       time.Duration
	hasMaxAge    bool
	minFresh     time.Duration
	hasMaxStale  bool
	maxStale     time.Duration // -1: any staleness is acceptable
}

func parseRequestDirectives(h http.Header) requestDirectives {
	cc := parseCacheControl(h)
	d := requestDirectives{
		noCache:      cc.has("no-cache"),
		noStore:      cc.has("no-store"),
		onlyIfCached: cc.has("only-if-cached"),
	}
	// Pragma: no-cache only counts when Cache-Control is absent (RFC 9111 5.4).
	if len(h.Values("Cache-Control")) == 0 && containsToken(h.Values("Pragma"), "no-cache") {
		d.noCache = true
	}
	d.maxAge, d.hasMaxAge = cc.seconds("max-age")
	d.minFresh, _ = cc.seconds("min-fresh")
	if value, ok := cc["max-stale"]; ok {
		d.hasMaxStale = true
		d.maxStale = -1
		if value != "" {
			d.maxStale, _ = cc.seconds("max-stale")
		}
	}
	return d
}

// heuristicallyCacheable are the status codes that may be stored without
// explicit freshness (RFC 9110 15.1). 206 is left out: ranges are not cached.
var heuristicallyCacheable = map[int]bool{
	200: true, 203: true, 204: true, 300: true, 301: true, 308: true,
	404: true, 405: true, 410: true, 414: true, 501: true,
}

// explicitlyCacheable are the other status codes stored only with explicit
// freshness information.
var explicitlyCacheable = map[int]bool{302: true, 303: true, 307: true}

// storable reports whether a shared cache may store resp for req, following
// RFC 9111 3 and 3.5. Responses that set cookies are never stored: replaying
// a session cookie to other clients is never what the origin meant.
func storable(req *http.Request, resp *http.Response, reqDir requestDirectives) bool {
	if reqDir.noStore {
		return false
	}
	cc := parseCacheControl(resp.Header)
	if cc.has("no-store") || cc.has("private") {
		return false
	}
	if req.Header.Get("Authorization") != "" && !cc.has("public") && !cc.has("must-revalidate") && !cc.has("s-maxage") {
		return false
	}
	if len(resp.Header.Values("Set-Cookie")) > 0 {
		return false
	}
	vary := varyNames(resp.Header)
	if slices.Contains(vary, "*") {
		return false
	}
	explicit := cc.has("s-maxage") || cc.has("max-age") || resp.Header.Get("Expires") != ""
	switch {
	case heuristicallyCacheable[resp.StatusCode]:
	case explicitlyCacheable[resp.StatusCode] && explicit:
	default:
		return false
	}
	// A response that is stale at once and cannot be validated is useless.
	lifetime := freshnessLifetime(resp.Header, resp.StatusCode, time.Time{})
	return lifetime > 0 || resp.Header.Get("ETag") != "" || resp.Header.Get("Last-Modified") != ""
}

// freshnessLifetime implements RFC 9111 4.2.1 for a shared cache. received
// replaces a missing or invalid Date header (zero: the lifetime is computed
// only from the headers).
func freshnessLifetime(h http.Header, status int, received time.Time) time.Duration {
	cc := parseCacheControl(h)
	if d, ok := cc.seconds("s-maxage"); ok {
		return d
	}
	if d, ok := cc.seconds("max-age"); ok {
		return d
	}
	date, err := http.ParseTime(h.Get("Date"))
	if err != nil {
		if received.IsZero() {
			received = time.Now()
		}
		date = received
	}
	if expiresValue := h.Get("Expires"); expiresValue != "" {
		expires, err := http.ParseTime(expiresValue)
		if err != nil {
			return 0 // an invalid Expires means already expired
		}
		return max(0, expires.Sub(date))
	}
	if !heuristicallyCacheable[status] && !cc.has("public") {
		return 0
	}
	lastModified, err := http.ParseTime(h.Get("Last-Modified"))
	if err != nil || !lastModified.Before(date) {
		return 0
	}
	return min(date.Sub(lastModified)/heuristicFraction, heuristicMax)
}

// initialAge is corrected_initial_age of RFC 9111 4.2.3.
func initialAge(h http.Header, requestTime, responseTime time.Time) time.Duration {
	apparentAge := time.Duration(0)
	if date, err := http.ParseTime(h.Get("Date")); err == nil {
		apparentAge = max(0, responseTime.Sub(date))
	}
	ageValue := time.Duration(0)
	if n, err := strconv.ParseInt(strings.TrimSpace(h.Get("Age")), 10, 64); err == nil && n > 0 {
		ageValue = time.Duration(min(n, 1<<31)) * time.Second
	}
	correctedAge := ageValue + max(0, responseTime.Sub(requestTime))
	return max(apparentAge, correctedAge)
}

// usable reports whether e can answer a request with directives d without
// contacting the origin (RFC 9111 4.2 and 5.2.1).
func usable(e *entry, d requestDirectives, age time.Duration) bool {
	if e.noCache || d.noCache {
		return false
	}
	if d.hasMaxAge && age > d.maxAge {
		return false
	}
	remaining := e.lifetime - age
	if remaining-d.minFresh > 0 {
		return true
	}
	if remaining > 0 || !d.hasMaxStale || e.revalidate {
		return false
	}
	return d.maxStale < 0 || -remaining <= d.maxStale
}

// varyNames returns the canonical header names listed in Vary, sorted.
func varyNames(h http.Header) []string {
	var names []string
	for _, line := range h.Values("Vary") {
		for _, name := range splitList(line) {
			if name == "*" {
				return []string{"*"}
			}
			names = append(names, textproto.CanonicalMIMEHeaderKey(name))
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// variantKey identifies the variant selected by the request headers named in
// vary. Whitespace around list members does not create a new variant.
func variantKey(h http.Header, vary []string) string {
	var b strings.Builder
	for _, name := range vary {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(strings.Join(splitList(strings.Join(h.Values(name), ",")), ","))
		b.WriteByte('\n')
	}
	return b.String()
}

// clientConditionals reports whether the client sent its own validators.
func clientConditionals(h http.Header) bool {
	return h.Get("If-None-Match") != "" || h.Get("If-Modified-Since") != "" ||
		h.Get("If-Match") != "" || h.Get("If-Unmodified-Since") != "" || h.Get("If-Range") != ""
}

// notModified evaluates If-None-Match and If-Modified-Since of a GET against
// a stored response (RFC 9110 13.2.2).
func notModified(req http.Header, stored http.Header) bool {
	if inm := req.Values("If-None-Match"); len(inm) > 0 {
		etag := stored.Get("ETag")
		for _, tag := range splitList(strings.Join(inm, ",")) {
			if tag == "*" || (etag != "" && weakMatch(tag, etag)) {
				return true
			}
		}
		return false
	}
	ims, err := http.ParseTime(req.Get("If-Modified-Since"))
	if err != nil {
		return false
	}
	lastModified, err := http.ParseTime(stored.Get("Last-Modified"))
	if err != nil {
		if lastModified, err = http.ParseTime(stored.Get("Date")); err != nil {
			return false
		}
	}
	return !lastModified.After(ims)
}

func weakMatch(a, b string) bool {
	return strings.TrimPrefix(a, "W/") == strings.TrimPrefix(b, "W/")
}

// hopByHop are removed before storing; headers listed in Connection too.
var hopByHop = []string{
	"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func storedHeader(h http.Header) http.Header {
	out := h.Clone()
	for _, line := range h.Values("Connection") {
		for _, name := range splitList(line) {
			out.Del(name)
		}
	}
	for _, name := range hopByHop {
		out.Del(name)
	}
	return out
}

// mergeNotModified updates stored headers with those of a 304 (RFC 9111
// 3.2), except the ones describing the stored body.
func mergeNotModified(stored, fresh http.Header) http.Header {
	out := stored.Clone()
	for name, values := range storedHeader(fresh) {
		switch name {
		case "Content-Length", "Content-Encoding", "Content-Range", "Content-Type":
			continue
		}
		out[name] = slices.Clone(values)
	}
	return out
}

// splitList splits a comma-separated header list, ignoring commas inside
// quoted strings (entity tags, no-cache="Set-Cookie, X-Foo").
func splitList(s string) []string {
	var out []string
	add := func(part string) {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	quoted, start := false, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if quoted {
				i++
			}
		case '"':
			quoted = !quoted
		case ',':
			if !quoted {
				add(s[start:i])
				start = i + 1
			}
		}
	}
	add(s[start:])
	return out
}

func containsToken(lines []string, token string) bool {
	for _, line := range lines {
		for _, part := range splitList(line) {
			if strings.EqualFold(part, token) {
				return true
			}
		}
	}
	return false
}

func equalFold(a, b []string) bool {
	return slices.EqualFunc(a, b, strings.EqualFold)
}
