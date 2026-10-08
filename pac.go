package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dop251/goja"
)

const (
	pacMaxSize      = 1 << 20 // 1 MiB: a PAC larger than this is not a PAC
	pacFetchTimeout = 15 * time.Second
	pacDNSTimeout   = 2 * time.Second
)

// pacEvalTimeout bounds each evaluation and the PAC top-level code (a var so
// tests can shorten it).
var pacEvalTimeout = 5 * time.Second

// pacRoute is one entry of the list returned by FindProxyForURL.
type pacRoute struct {
	Direct bool
	Proxy  *url.URL // scheme http or https, without credentials
}

func (r pacRoute) String() string {
	if r.Direct {
		return "DIRECT"
	}
	return r.Proxy.String()
}

// parsePACResult turns "PROXY a:8080; PROXY b:8080; DIRECT" into routes.
// SOCKS entries and unknown keywords are skipped: the proxy cannot use them.
func parsePACResult(result string) ([]pacRoute, error) {
	var routes []pacRoute
	for _, part := range strings.Split(result, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "DIRECT":
			routes = append(routes, pacRoute{Direct: true})
		case "PROXY", "HTTP", "HTTPS":
			if len(fields) < 2 {
				continue
			}
			scheme := "http"
			if strings.EqualFold(fields[0], "HTTPS") {
				scheme = "https"
			}
			u, err := url.Parse(scheme + "://" + fields[1])
			if err != nil || u.Host == "" {
				continue
			}
			routes = append(routes, pacRoute{Proxy: u})
		}
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("pac: no usable entry in %q", result)
	}
	return routes, nil
}

// pacRuntime is a goja runtime with the PAC loaded. goja runtimes are not
// goroutine-safe, so every evaluation takes one from the engine's pool.
type pacRuntime struct {
	vm   *goja.Runtime
	find goja.Callable
}

type pacEngine struct {
	prog *goja.Program
	pool sync.Pool
}

func newPACEngine(script string) (*pacEngine, error) {
	prog, err := goja.Compile("proxy.pac", script, false)
	if err != nil {
		return nil, fmt.Errorf("compile PAC: %w", err)
	}
	e := &pacEngine{prog: prog}
	e.pool.New = func() any {
		rt, err := e.newRuntime()
		if err != nil {
			return nil
		}
		return rt
	}
	// Fail at load time, not on the first request, if the script is broken.
	rt, err := e.newRuntime()
	if err != nil {
		return nil, err
	}
	e.pool.Put(rt)
	return e, nil
}

func (e *pacEngine) newRuntime() (*pacRuntime, error) {
	vm := goja.New()
	registerPACBuiltins(vm)

	timer := time.AfterFunc(pacEvalTimeout, func() { vm.Interrupt("pac timeout") })
	_, err := vm.RunProgram(e.prog)
	if !timer.Stop() {
		return nil, errors.New("PAC top-level code timed out")
	}
	if err != nil {
		return nil, fmt.Errorf("run PAC: %w", err)
	}
	find, ok := goja.AssertFunction(vm.Get("FindProxyForURL"))
	if !ok {
		return nil, errors.New("PAC does not define FindProxyForURL")
	}
	return &pacRuntime{vm: vm, find: find}, nil
}

// FindProxy evaluates FindProxyForURL(rawURL, host).
func (e *pacEngine) FindProxy(rawURL, host string) ([]pacRoute, error) {
	rt, _ := e.pool.Get().(*pacRuntime)
	if rt == nil {
		return nil, errors.New("pac: cannot create runtime")
	}
	timer := time.AfterFunc(pacEvalTimeout, func() { rt.vm.Interrupt("pac timeout") })
	val, err := rt.find(goja.Undefined(), rt.vm.ToValue(rawURL), rt.vm.ToValue(host))
	inTime := timer.Stop()
	if err != nil || !inTime {
		// Never return an interrupted runtime to the pool.
		if err == nil {
			err = errors.New("pac: evaluation timed out")
		}
		return nil, err
	}
	e.pool.Put(rt)
	return parsePACResult(val.String())
}

// registerPACBuiltins defines the functions a PAC expects from the browser.
// Not implemented: weekdayRange, dateRange, timeRange (a PAC calling them
// raises a ReferenceError, which is reported as an evaluation error).
func registerPACBuiltins(vm *goja.Runtime) {
	vm.Set("isPlainHostName", func(host string) bool { return !strings.Contains(host, ".") })
	vm.Set("dnsDomainIs", func(host, domain string) bool { return strings.HasSuffix(host, domain) })
	vm.Set("localHostOrDomainIs", func(host, hostdom string) bool {
		return host == hostdom || (!strings.Contains(host, ".") && strings.HasPrefix(hostdom, host+"."))
	})
	vm.Set("dnsDomainLevels", func(host string) int { return strings.Count(host, ".") })
	vm.Set("shExpMatch", func(s, pattern string) bool { return globToRegexp(pattern).MatchString(s) })
	vm.Set("isResolvable", func(host string) bool { return resolveIPv4(host) != "" })
	vm.Set("myIpAddress", localIPv4)
	vm.Set("isInNet", isInNet)
	vm.Set("alert", func(goja.FunctionCall) goja.Value { return goja.Undefined() })
	vm.Set("dnsResolve", func(call goja.FunctionCall) goja.Value {
		if ip := resolveIPv4(call.Argument(0).String()); ip != "" {
			return vm.ToValue(ip)
		}
		return goja.Null() // what browsers return on failure
	})
}

// globToRegexp converts a shell glob (only * and ?) into an anchored regexp.
func globToRegexp(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?s)^")
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// resolveIPv4 returns the first IPv4 address of host, or "" on failure.
// The lookup is bounded: PAC built-ins are synchronous and must not hang.
func resolveIPv4(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), pacDNSTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

// localIPv4 picks the outgoing interface address. A UDP "connect" only
// consults the routing table: no packet is sent.
func localIPv4() string {
	conn, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return "127.0.0.1"
}

func isInNet(host, pattern, mask string) bool {
	ip := net.ParseIP(resolveIPv4(host)).To4()
	pat := net.ParseIP(pattern).To4()
	m := net.ParseIP(mask).To4()
	if ip == nil || pat == nil || m == nil {
		return false
	}
	for i := range ip {
		if ip[i]&m[i] != pat[i]&m[i] {
			return false
		}
	}
	return true
}

// pacManager loads the PAC from a URL or file and reloads it periodically.
// A failed reload keeps the previous script.
type pacManager struct {
	src    string
	logger *log.Logger
	client *http.Client
	engine atomic.Pointer[pacEngine]
}

func newPACManager(src string, logger *log.Logger) (*pacManager, error) {
	m := &pacManager{
		src:    src,
		logger: logger,
		client: &http.Client{
			Timeout: pacFetchTimeout,
			// The PAC is fetched directly: it is what decides about proxies.
			Transport: &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second},
		},
	}
	if err := m.Refresh(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *pacManager) fetch() (string, error) {
	var r io.Reader
	if strings.HasPrefix(m.src, "http://") || strings.HasPrefix(m.src, "https://") {
		resp, err := m.client.Get(m.src)
		if err != nil {
			return "", fmt.Errorf("fetch PAC: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("fetch PAC: %s", resp.Status)
		}
		r = resp.Body
	} else {
		f, err := os.Open(strings.TrimPrefix(m.src, "file://"))
		if err != nil {
			return "", fmt.Errorf("open PAC: %w", err)
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, pacMaxSize+1))
	if err != nil {
		return "", fmt.Errorf("read PAC: %w", err)
	}
	if len(data) > pacMaxSize {
		return "", fmt.Errorf("PAC larger than %d bytes", pacMaxSize)
	}
	return string(data), nil
}

func (m *pacManager) Refresh() error {
	script, err := m.fetch()
	if err != nil {
		return err
	}
	engine, err := newPACEngine(script)
	if err != nil {
		return err
	}
	m.engine.Store(engine)
	return nil
}

// Run reloads the PAC every interval until ctx is cancelled.
func (m *pacManager) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Refresh(); err != nil {
				m.logger.Printf("FAILED PAC reload, keeping the previous script: %v", err)
			} else {
				m.logger.Printf("PAC reloaded from %s", m.src)
			}
		}
	}
}

func (m *pacManager) FindProxy(rawURL, host string) ([]pacRoute, error) {
	return m.engine.Load().FindProxy(rawURL, host)
}
