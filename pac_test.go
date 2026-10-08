package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPAC = `
function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || dnsDomainIs(host, ".corp.example")) return "DIRECT";
  if (shExpMatch(url, "*/api/*")) return "PROXY a.example:8080; PROXY b.example:8080";
  if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
  return "PROXY def.example:3128; SOCKS5 s.example:1080";
}`

func routesString(routes []pacRoute) string {
	parts := make([]string, len(routes))
	for i, r := range routes {
		parts[i] = r.String()
	}
	return strings.Join(parts, ",")
}

func TestParsePACResult(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"DIRECT", "DIRECT", false},
		{"PROXY a:8080; DIRECT", "http://a:8080,DIRECT", false},
		{" proxy a:1 ;HTTPS b:2;; ", "http://a:1,https://b:2", false},
		{"SOCKS5 s:1080; PROXY a:1", "http://a:1", false}, // SOCKS skipped
		{"SOCKS s:1080", "", true},
		{"", "", true},
		{"undefined", "", true},
	}
	for _, tt := range tests {
		got, err := parsePACResult(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parsePACResult(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && routesString(got) != tt.want {
			t.Errorf("parsePACResult(%q) = %s, want %s", tt.in, routesString(got), tt.want)
		}
	}
}

func TestPACEngine(t *testing.T) {
	engine, err := newPACEngine(testPAC)
	if err != nil {
		t.Fatal(err)
	}
	// IP hosts only: no test depends on DNS.
	tests := []struct{ url, host, want string }{
		{"http://intranet/", "intranet", "DIRECT"},
		{"http://x.corp.example/", "x.corp.example", "DIRECT"},
		{"http://8.8.8.8/api/v1", "8.8.8.8", "http://a.example:8080,http://b.example:8080"},
		{"http://10.1.2.3/", "10.1.2.3", "DIRECT"},
		{"http://8.8.8.8/", "8.8.8.8", "http://def.example:3128"},
	}
	for _, tt := range tests {
		got, err := engine.FindProxy(tt.url, tt.host)
		if err != nil {
			t.Errorf("FindProxy(%q) error = %v", tt.url, err)
			continue
		}
		if routesString(got) != tt.want {
			t.Errorf("FindProxy(%q) = %s, want %s", tt.url, routesString(got), tt.want)
		}
	}
}

func TestPACEngineRejectsBrokenScripts(t *testing.T) {
	for name, script := range map[string]string{
		"syntax error":   "function FindProxyForURL(",
		"no entry point": "var x = 1;",
		"throws on load": "throw new Error('boom');",
	} {
		if _, err := newPACEngine(script); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestPACEvaluationTimeout(t *testing.T) {
	old := pacEvalTimeout
	pacEvalTimeout = 100 * time.Millisecond
	defer func() { pacEvalTimeout = old }()

	engine, err := newPACEngine("function FindProxyForURL(u, h) { while (true) {} }")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := engine.FindProxy("http://8.8.8.8/", "8.8.8.8"); err == nil {
		t.Fatal("expected a timeout error")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("evaluation was not interrupted in time: %s", time.Since(start))
	}
}

func TestProxyServerRouteWithPAC(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.pac")
	bad := filepath.Join(dir, "bad.pac")
	os.WriteFile(good, []byte(testPAC), 0o600)
	os.WriteFile(bad, []byte("function FindProxyForURL(u, h) { return missingFn(); }"), 0o600)
	logger := log.New(io.Discard, "", 0)

	srv, err := newProxyServer(Config{PACURL: good}, logger)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := srv.route("http://8.8.8.8/", "8.8.8.8")
	if err != nil || routesString(routes) != "http://def.example:3128" {
		t.Fatalf("route() = %v, %v", routes, err)
	}

	// PAC failure: error, never a silent DIRECT.
	srv, err = newProxyServer(Config{PACURL: bad}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.route("http://8.8.8.8/", "8.8.8.8"); err == nil {
		t.Fatal("expected an error when the PAC fails")
	}

	// pac_url and parent_proxy are mutually exclusive.
	if _, err := newProxyServer(Config{PACURL: good, ParentProxy: "http://parent.example:3128"}, logger); err == nil {
		t.Fatal("expected an error when both pac_url and parent_proxy are set")
	}
}

func TestProxyServerRoutePriority(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.pac")
	os.WriteFile(good, []byte(testPAC), 0o600)
	logger := log.New(io.Discard, "", 0)

	tests := []struct {
		name string
		cfg  Config
		host string
		want string
	}{
		{"no parent and no PAC", Config{}, "8.8.8.8", "DIRECT"},
		{"parent only", Config{ParentProxy: "http://parent.example:3128"}, "8.8.8.8", "http://parent.example:3128"},
		{"direct_hosts over parent", Config{ParentProxy: "http://parent.example:3128", DirectHosts: []string{"corp.example"}}, "a.corp.example", "DIRECT"},
		{"direct_hosts over PAC", Config{PACURL: good, DirectHosts: []string{"8.8.8.8"}}, "8.8.8.8", "DIRECT"},
	}
	for _, tt := range tests {
		srv, err := newProxyServer(tt.cfg, logger)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		routes, err := srv.route("http://"+tt.host+"/", tt.host)
		if err != nil || routesString(routes) != tt.want {
			t.Errorf("%s: route() = %s, %v, want %s", tt.name, routesString(routes), err, tt.want)
		}
	}
}

func TestProxyHTTPFailsOverPACRoutes(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		io.WriteString(w, r.Method+" "+string(body))
	}))
	defer target.Close()

	// Port 1 refuses connections: the first entry fails before anything is sent.
	pacFile := filepath.Join(t.TempDir(), "failover.pac")
	os.WriteFile(pacFile, []byte(`function FindProxyForURL(u, h) { return "PROXY 127.0.0.1:1; DIRECT"; }`), 0o600)
	proxy, err := newProxyServer(Config{PACURL: pacFile}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.transport.CloseIdleConnections()
	server := httptest.NewServer(proxy)
	defer server.Close()
	proxyURL, _ := url.Parse(server.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()

	for _, tt := range []struct{ method, body string }{{"GET", ""}, {"POST", "payload"}} {
		req, _ := http.NewRequest(tt.method, target.URL+"/", strings.NewReader(tt.body))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if want := tt.method + " " + tt.body; resp.StatusCode != http.StatusOK || string(got) != want {
			t.Errorf("%s: response = %d %q, want 200 %q", tt.method, resp.StatusCode, got, want)
		}
	}
}

func TestIsDialError(t *testing.T) {
	_, err := net.DialTimeout("tcp", "127.0.0.1:1", time.Second)
	if err == nil {
		t.Skip("something listens on 127.0.0.1:1")
	}
	if !isDialError(fmt.Errorf("wrapped: %w", &net.OpError{Op: "proxyconnect", Err: err})) {
		t.Errorf("isDialError(proxyconnect dial failure) = false, want true")
	}
	if isDialError(errors.New("Proxy Authentication Required")) || isDialError(&net.OpError{Op: "read", Err: io.EOF}) {
		t.Errorf("isDialError must be false for errors after the connection is established")
	}
}

func TestConnectPACURL(t *testing.T) {
	tests := []struct{ target, url, host string }{
		{"example.com:443", "https://example.com/", "example.com"},
		{"example.com:8443", "https://example.com:8443/", "example.com"},
		{"[::1]:443", "https://[::1]/", "::1"},
		{"[::1]:8443", "https://[::1]:8443/", "::1"},
	}
	for _, tt := range tests {
		gotURL, gotHost := connectPACURL(tt.target)
		if gotURL != tt.url || gotHost != tt.host {
			t.Errorf("connectPACURL(%q) = %q, %q; want %q, %q", tt.target, gotURL, gotHost, tt.url, tt.host)
		}
	}
}

func TestConnectStopsWhenProxyRefuses(t *testing.T) {
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer refusing.Close()
	reached := make(chan struct{}, 1)
	direct, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	go func() {
		if conn, err := direct.Accept(); err == nil {
			reached <- struct{}{}
			conn.Close()
		}
	}()

	pacFile := filepath.Join(t.TempDir(), "refuse.pac")
	os.WriteFile(pacFile, []byte(`function FindProxyForURL(u, h) { return "PROXY `+strings.TrimPrefix(refusing.URL, "http://")+`; DIRECT"; }`), 0o600)
	srv, err := newProxyServer(Config{PACURL: pacFile}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	// A refusal is an answer, not a connection failure: DIRECT must not be tried.
	if _, _, err := srv.dialConnectUpstream(direct.Addr().String()); !errors.Is(err, errParentConnectRefused) {
		t.Fatalf("dialConnectUpstream() error = %v, want %v", err, errParentConnectRefused)
	}
	select {
	case <-reached:
		t.Fatal("the DIRECT entry was tried after the proxy refused the CONNECT")
	case <-time.After(100 * time.Millisecond):
	}
}
