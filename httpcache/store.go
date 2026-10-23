// Package httpcache is an in-memory shared HTTP cache for a forward proxy. It
// follows the caching rules of RFC 9111 for a shared cache (freshness,
// validation, Vary, invalidation) and bounds its memory with GDSF
// (Greedy-Dual-Size-Frequency) replacement.
package httpcache

import (
	"container/heap"
	"net/http"
	"sync"
	"time"
)

// entryOverhead approximates the memory used by an entry besides its body and
// headers (structs, map slots, heap slot).
const entryOverhead = 512

// entry is one stored response. Its fields are never changed after insertion,
// except the replacement bookkeeping under Cache.mu: an update replaces the
// entry, so a response being served from an old one stays consistent.
type entry struct {
	url         string // primary key
	variant     string // secondary key: the request headers named by Vary
	status      int
	statusText  string
	header      http.Header
	body        []byte
	requestTime time.Time // when the request that produced it was sent
	// when the response (or the 304 that last validated it) was received
	responseTime time.Time
	initialAge   time.Duration // corrected_initial_age of RFC 9111 4.2.3
	lifetime     time.Duration // freshness lifetime
	noCache      bool          // must be validated before every use
	revalidate   bool          // must-revalidate, proxy-revalidate or s-maxage: never served stale
	size         int64

	// GDSF bookkeeping, protected by Cache.mu
	freq     float64
	priority float64
	index    int // position in the heap, -1 when not stored
}

func (e *entry) age(now time.Time) time.Duration {
	return e.initialAge + max(0, now.Sub(e.responseTime))
}

func (e *entry) hasValidators() bool {
	return e.header.Get("ETag") != "" || e.header.Get("Last-Modified") != ""
}

// urlGroup holds the variants stored for one URL and the header names its
// latest response listed in Vary.
type urlGroup struct {
	vary     []string
	variants map[string]*entry
}

// Stats is a snapshot of the cache counters.
type Stats struct {
	Entries     int
	Bytes       int64
	MaxBytes    int64
	Hits        uint64 // served from the cache, including after a 304
	Misses      uint64 // forwarded and possibly stored
	Evictions   uint64
	Revalidated uint64
}

// Cache is safe for concurrent use.
type Cache struct {
	maxBytes  int64
	maxObject int64
	now       func() time.Time

	mu     sync.Mutex
	groups map[string]*urlGroup
	heap   entryHeap
	used   int64
	// GDSF inflation value: the priority of the last evicted entry. New and
	// accessed entries start from it, so entries that are no longer used age
	// out even if they were popular once.
	clock float64
	stats Stats
}

// New returns a cache that keeps at most maxBytes of responses in memory. A
// single response larger than an eighth of maxBytes is not stored, so one
// download cannot flush the whole cache.
func New(maxBytes int64) *Cache {
	return &Cache{
		maxBytes:  maxBytes,
		maxObject: maxBytes / 8,
		now:       time.Now,
		groups:    make(map[string]*urlGroup),
	}
}

func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Entries = len(c.heap)
	s.Bytes = c.used
	s.MaxBytes = c.maxBytes
	return s
}

// lookup returns the variant of url matching req, or nil.
func (c *Cache) lookup(url string, req *http.Request) *entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	g := c.groups[url]
	if g == nil {
		return nil
	}
	return g.variants[variantKey(req.Header, g.vary)]
}

// touch records a use of e for the replacement policy.
func (c *Cache) touch(e *entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.index < 0 {
		return // replaced or evicted meanwhile
	}
	e.freq++
	e.priority = c.clock + e.freq/float64(e.size)
	heap.Fix(&c.heap, e.index)
}

// store inserts e, replacing the variant with the same keys. vary is the
// Vary list of the response: a different list from the stored one drops the
// old variants, which were selected with other headers.
func (c *Cache) store(e *entry, vary []string) {
	e.size = entrySize(e)
	if e.size > c.maxObject {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	g := c.groups[e.url]
	if g != nil && !equalFold(g.vary, vary) {
		c.removeGroupLocked(e.url)
		g = nil
	}
	if g == nil {
		g = &urlGroup{vary: vary, variants: make(map[string]*entry)}
		c.groups[e.url] = g
	}
	e.freq = 1
	if old := g.variants[e.variant]; old != nil {
		// A refreshed response keeps the popularity of the one it replaces.
		e.freq = old.freq
		c.removeLocked(old)
	}
	for c.used+e.size > c.maxBytes && len(c.heap) > 0 {
		victim := c.heap[0]
		c.clock = victim.priority
		c.removeLocked(victim)
		c.stats.Evictions++
	}
	// removeLocked may have dropped the group with its last variant.
	if c.groups[e.url] == nil {
		c.groups[e.url] = g
	}
	e.priority = c.clock + e.freq/float64(e.size)
	g.variants[e.variant] = e
	heap.Push(&c.heap, e)
	c.used += e.size
}

// remove drops e if it is still stored.
func (c *Cache) remove(e *entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.index >= 0 {
		c.removeLocked(e)
	}
}

// invalidate drops every variant stored for url.
func (c *Cache) invalidate(url string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeGroupLocked(url)
}

func (c *Cache) removeGroupLocked(url string) {
	g := c.groups[url]
	if g == nil {
		return
	}
	for _, e := range g.variants {
		c.removeLocked(e)
	}
	delete(c.groups, url)
}

func (c *Cache) removeLocked(e *entry) {
	heap.Remove(&c.heap, e.index)
	c.used -= e.size
	if g := c.groups[e.url]; g != nil && g.variants[e.variant] == e {
		delete(g.variants, e.variant)
		if len(g.variants) == 0 {
			delete(c.groups, e.url)
		}
	}
}

func entrySize(e *entry) int64 {
	size := int64(entryOverhead + len(e.body) + len(e.url) + len(e.variant))
	for name, values := range e.header {
		for _, v := range values {
			size += int64(len(name) + len(v))
		}
	}
	return size
}

// entryHeap is a min-heap on the GDSF priority: the root is the next victim.
type entryHeap []*entry

func (h entryHeap) Len() int           { return len(h) }
func (h entryHeap) Less(i, j int) bool { return h[i].priority < h[j].priority }
func (h entryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *entryHeap) Push(x any) {
	e := x.(*entry)
	e.index = len(*h)
	*h = append(*h, e)
}

func (h *entryHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	e.index = -1
	return e
}
