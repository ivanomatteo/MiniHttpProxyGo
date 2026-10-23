package httpcache

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Status tells how the cache handled a request, for logging.
type Status string

const (
	Bypass      Status = "BYPASS"      // not cacheable: forwarded untouched
	Miss        Status = "MISS"        // forwarded; the response may have been stored
	Hit         Status = "HIT"         // served from the cache
	Revalidated Status = "REVALIDATED" // validated with the origin (304) and served from the cache
)

// RoundTrip answers req from the cache or sends it with next, storing the
// response when allowed. req must have an absolute URL. Only GET requests
// without body, Range or Upgrade use the cache; unsafe methods invalidate the
// stored responses of their target.
func (c *Cache) RoundTrip(req *http.Request, next http.RoundTripper) (*http.Response, Status, error) {
	if req.Method != http.MethodGet {
		resp, err := next.RoundTrip(req)
		if err == nil && isUnsafe(req.Method) && resp.StatusCode < 400 {
			c.invalidateTargets(req.URL, resp.Header)
		}
		return resp, Bypass, err
	}
	if (req.Body != nil && req.Body != http.NoBody) || req.Header.Get("Range") != "" || req.Header.Get("Upgrade") != "" {
		resp, err := next.RoundTrip(req)
		return resp, Bypass, err
	}

	key := cacheKey(req.URL)
	dir := parseRequestDirectives(req.Header)
	now := c.now()
	stored := c.lookup(key, req)
	if stored != nil {
		if usable(stored, dir, stored.age(now)) {
			c.touch(stored)
			c.count(func(s *Stats) { s.Hits++ })
			return stored.response(req, now), Hit, nil
		}
	}
	if dir.onlyIfCached {
		c.count(func(s *Stats) { s.Misses++ })
		return gatewayTimeout(req), Miss, nil
	}

	out := req
	validating := stored != nil && stored.hasValidators() && !clientConditionals(req.Header)
	if validating {
		out = req.Clone(req.Context())
		if etag := stored.header.Get("ETag"); etag != "" {
			out.Header.Set("If-None-Match", etag)
		}
		if lastModified := stored.header.Get("Last-Modified"); lastModified != "" {
			out.Header.Set("If-Modified-Since", lastModified)
		}
	}
	requestTime := now
	resp, err := next.RoundTrip(out)
	if err != nil {
		return nil, Miss, err
	}
	responseTime := c.now()

	if validating && resp.StatusCode == http.StatusNotModified {
		resp.Body.Close()
		header := mergeNotModified(stored.header, resp.Header)
		refreshed := c.newEntry(req, stored.status, stored.statusText, header, requestTime, responseTime)
		refreshed.body = stored.body
		// The origin may have made the response no longer storable.
		if storable(req, &http.Response{StatusCode: stored.status, Header: header}, dir) {
			c.store(refreshed, varyNames(header))
		} else {
			c.remove(stored)
		}
		c.count(func(s *Stats) { s.Hits++; s.Revalidated++ })
		return refreshed.response(req, responseTime), Revalidated, nil
	}

	c.count(func(s *Stats) { s.Misses++ })
	if !storable(req, resp, dir) {
		// A 304 answers the client's own validators and says nothing about
		// the stored response; a 5xx is a failure, not a new representation.
		if stored != nil && resp.StatusCode != http.StatusNotModified && resp.StatusCode < 500 {
			// The stored response was superseded by one that cannot be kept.
			c.remove(stored)
		}
		return resp, Miss, nil
	}
	if resp.ContentLength > c.maxObject {
		return resp, Miss, nil
	}
	e := c.newEntry(req, resp.StatusCode, resp.Status, storedHeader(resp.Header), requestTime, responseTime)
	vary := varyNames(resp.Header)
	if resp.Body == nil || resp.Body == http.NoBody {
		c.store(e, vary)
		return resp, Miss, nil
	}
	resp.Body = &captureBody{
		ReadCloser: resp.Body,
		limit:      c.maxObject,
		done: func(body []byte) {
			e.body = body
			c.store(e, vary)
		},
	}
	return resp, Miss, nil
}

func (c *Cache) count(update func(*Stats)) {
	c.mu.Lock()
	update(&c.stats)
	c.mu.Unlock()
}

func (c *Cache) newEntry(req *http.Request, status int, statusText string, header http.Header, requestTime, responseTime time.Time) *entry {
	cc := parseCacheControl(header)
	return &entry{
		url:          cacheKey(req.URL),
		variant:      variantKey(req.Header, varyNames(header)),
		status:       status,
		statusText:   statusText,
		header:       header,
		requestTime:  requestTime,
		responseTime: responseTime,
		initialAge:   initialAge(header, requestTime, responseTime),
		lifetime:     freshnessLifetime(header, status, responseTime),
		noCache:      cc.has("no-cache"),
		revalidate:   cc.has("must-revalidate") || cc.has("proxy-revalidate") || cc.has("s-maxage"),
		index:        -1,
	}
}

// response builds the answer to req from e: a 304 when the client's own
// validators match, otherwise the stored response.
func (e *entry) response(req *http.Request, now time.Time) *http.Response {
	age := strconv.FormatInt(int64(e.age(now)/time.Second), 10)
	if e.status == http.StatusOK && clientConditionals(req.Header) && notModified(req.Header, e.header) {
		h := http.Header{}
		for _, name := range []string{"Cache-Control", "Content-Location", "Date", "ETag", "Expires", "Last-Modified", "Vary"} {
			if values := e.header.Values(name); len(values) > 0 {
				h[http.CanonicalHeaderKey(name)] = values
			}
		}
		h.Set("Age", age)
		return &http.Response{
			Status: "304 Not Modified", StatusCode: http.StatusNotModified,
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: h, Body: http.NoBody, Request: req,
		}
	}
	h := e.header.Clone()
	h.Set("Age", age)
	h.Set("Content-Length", strconv.Itoa(len(e.body)))
	return &http.Response{
		Status: e.statusText, StatusCode: e.status,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: h, Body: io.NopCloser(bytes.NewReader(e.body)),
		ContentLength: int64(len(e.body)), Request: req,
	}
}

// invalidateTargets drops the responses stored for the target of an unsafe
// request and for its Location and Content-Location on the same origin
// (RFC 9111 4.4).
func (c *Cache) invalidateTargets(target *url.URL, h http.Header) {
	c.invalidate(cacheKey(target))
	for _, name := range []string{"Location", "Content-Location"} {
		ref, err := url.Parse(h.Get(name))
		if err != nil || h.Get(name) == "" {
			continue
		}
		if u := target.ResolveReference(ref); strings.EqualFold(u.Host, target.Host) && u.Scheme == target.Scheme {
			c.invalidate(cacheKey(u))
		}
	}
}

func isUnsafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	}
	return true
}

func cacheKey(u *url.URL) string {
	k := *u
	k.Fragment, k.RawFragment, k.User = "", "", nil
	k.Scheme = strings.ToLower(k.Scheme)
	k.Host = strings.ToLower(k.Host)
	return k.String()
}

func gatewayTimeout(req *http.Request) *http.Response {
	body := "Not in cache (only-if-cached)\n"
	return &http.Response{
		Status:     fmt.Sprintf("%d %s", http.StatusGatewayTimeout, http.StatusText(http.StatusGatewayTimeout)),
		StatusCode: http.StatusGatewayTimeout,
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// captureBody copies the body while it is read and hands it to done once it
// was read completely. A body larger than limit, or closed early, is not
// stored.
type captureBody struct {
	io.ReadCloser
	buf      bytes.Buffer
	limit    int64
	overflow bool
	finished bool
	done     func([]byte)
}

func (b *captureBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 && !b.overflow {
		if int64(b.buf.Len()+n) > b.limit {
			b.overflow = true
			b.buf = bytes.Buffer{}
		} else {
			b.buf.Write(p[:n])
		}
	}
	if err == io.EOF && !b.overflow && !b.finished {
		b.finished = true
		b.done(bytes.Clone(b.buf.Bytes()))
		b.buf = bytes.Buffer{}
	}
	return n, err
}
