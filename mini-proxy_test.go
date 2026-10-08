package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandleConnectDetectsParentAuthenticationFailure(t *testing.T) {
	err := parentConnectStatusError("HTTP/1.1 407 Proxy Authentication Required")
	if !errors.Is(err, errParentProxyAuthentication) {
		t.Fatalf("parentConnectStatusError() error = %v, want authentication failure", err)
	}
	if err := parentConnectStatusError("HTTP/1.1 403 Forbidden"); err != nil {
		t.Fatalf("parentConnectStatusError() error = %v, want nil", err)
	}
}

func TestHandleConnectPreservesBufferedTunnelBytes(t *testing.T) {
	parentListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer parentListener.Close()

	parentDone := make(chan error, 1)
	go func() {
		conn, err := parentListener.Accept()
		if err != nil {
			parentDone <- err
			return
		}
		defer conn.Close()
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			parentDone <- err
			return
		}
		request.Body.Close()
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\nProxy-Agent: test\r\n\r\n"); err != nil {
			parentDone <- err
			return
		}
		got := make([]byte, len("CLIENT"))
		if _, err := io.ReadFull(conn, got); err != nil {
			parentDone <- err
			return
		}
		if string(got) != "CLIENT" {
			parentDone <- errors.New("parent received incorrect tunneled bytes")
			return
		}
		_, err = io.WriteString(conn, "SERVER")
		parentDone <- err
	}()

	proxy, err := newProxyServer(Config{ParentProxy: "http://" + parentListener.Addr().String()}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := proxy.handleConnect(w, r); err != nil {
			t.Errorf("handleConnect() error = %v", err)
		}
	}))
	defer proxyServer.Close()

	proxyAddr := strings.TrimPrefix(proxyServer.URL, "http://")
	clientConn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	if err := clientConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// CONNECT and the first tunnel bytes deliberately share a write. The HTTP
	// server commonly reads CLIENT into its bufio.Reader while parsing headers.
	if _, err := io.WriteString(clientConn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nCLIENT"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(clientConn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	got := make([]byte, len("SERVER"))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "SERVER" {
		t.Fatalf("client received %q, want SERVER", got)
	}
	clientConn.Close()

	select {
	case err := <-parentDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("parent did not receive buffered tunnel bytes")
	}
}

func TestResolveCredentials(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		serviceMode bool
		input       string
		password    string
		wantUser    string
		wantPass    string
		wantPrompt  string
		wantErr     bool
	}{
		{name: "empty credentials", cfg: Config{}, wantUser: "", wantPass: ""},
		{name: "fixed credentials", cfg: Config{Username: "user", Password: "secret"}, wantUser: "user", wantPass: "secret"},
		{name: "ask both", cfg: Config{Username: "[ask]", Password: "[ask]"}, input: "alice\n", password: "secret", wantUser: "alice", wantPass: "secret", wantPrompt: "Parent proxy username: Parent proxy password: "},
		{name: "ask password only", cfg: Config{Username: "alice", Password: "[ask]"}, password: "secret", wantUser: "alice", wantPass: "secret", wantPrompt: "Parent proxy password: "},
		{name: "ask in service", cfg: Config{Username: "[ask]", Password: "secret"}, serviceMode: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			passwordReads := 0
			err := resolveCredentials(&tt.cfg, tt.serviceMode, strings.NewReader(tt.input), &output, func() (string, error) {
				passwordReads++
				return tt.password, nil
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.cfg.Username != tt.wantUser || tt.cfg.Password != tt.wantPass {
				t.Fatalf("credentials = %q/%q, want %q/%q", tt.cfg.Username, tt.cfg.Password, tt.wantUser, tt.wantPass)
			}
			if output.String() != tt.wantPrompt {
				t.Fatalf("prompt = %q, want %q", output.String(), tt.wantPrompt)
			}
			if strings.Contains(output.String(), tt.wantPass) && tt.wantPass != "" {
				t.Fatalf("password was written to console output: %q", output.String())
			}
			wantPasswordReads := 0
			if tt.cfg.Password != "" && tt.wantPass == tt.password {
				wantPasswordReads = 1
			}
			if passwordReads != wantPasswordReads {
				t.Fatalf("password reader called %d times, want %d", passwordReads, wantPasswordReads)
			}
		})
	}
}

func TestLoadConfigEncryptsPlainPasswordAndDecryptsIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	initial := `{"listen_addr":":3128","parent_proxy":"http://proxy:8080","username":"alice","password":"very-secret","custom":"preserved"}`
	if err := os.WriteFile(path, []byte(initial), 0o640); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "very-secret" {
		t.Fatalf("password = %q", cfg.Password)
	}

	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(updated, []byte("very-secret")) {
		t.Fatalf("plain password remains in config: %s", updated)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(updated, &raw); err != nil {
		t.Fatal(err)
	}
	var seed string
	if err := json.Unmarshal(raw["key_seed"], &seed); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9]{20}$`).MatchString(seed) {
		t.Fatalf("invalid key_seed %q", seed)
	}
	var encrypted encryptedPassword
	if err := json.Unmarshal(raw["password"], &encrypted); err != nil || encrypted.Encrypted == "" {
		t.Fatalf("invalid encrypted password: %s", raw["password"])
	}
	if string(raw["custom"]) != `"preserved"` {
		t.Fatalf("unknown field was not preserved")
	}

	loadedAgain, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loadedAgain.Password != "very-secret" {
		t.Fatalf("decrypted password = %q", loadedAgain.Password)
	}
}

func TestLoadConfigDoesNotEncryptAsk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"username":"[ask]","password":"[ask]"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(updated, &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["password"]) != `"[ask]"` {
		t.Fatalf("ask password changed to %s", raw["password"])
	}
	if _, ok := raw["key_seed"]; !ok {
		t.Fatal("key_seed was not added")
	}
}

func TestLoadConfigStopIfAuthFail(t *testing.T) {
	tests := []struct {
		name string
		json string
		want bool
	}{
		{name: "defaults to true", json: `{}`, want: true},
		{name: "explicit true", json: `{"stop_if_auth_fail":true}`, want: true},
		{name: "explicit false", json: `{"stop_if_auth_fail":false}`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tt.json), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.StopIfAuthFail != tt.want {
				t.Fatalf("StopIfAuthFail = %v, want %v", cfg.StopIfAuthFail, tt.want)
			}
		})
	}
}

func TestLoadConfigAcceptConnectionFrom(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    []string
		wantErr bool
	}{
		{name: "defaults to loopback", json: `{}`, want: []string{"127.0.0.1", "::1"}},
		{name: "explicit list", json: `{"accept_connection_from":["192.168.1.1","192.168.20.0/24"]}`, want: []string{"192.168.1.1", "192.168.20.0/24"}},
		{name: "empty list", json: `{"accept_connection_from":[]}`, wantErr: true},
		{name: "invalid ip", json: `{"accept_connection_from":["192.168.1.300"]}`, wantErr: true},
		{name: "invalid cidr", json: `{"accept_connection_from":["10.0.0.0/33"]}`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tt.json), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadConfig(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("loadConfig() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(cfg.AcceptConnectionFrom, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("AcceptConnectionFrom = %v, want %v", cfg.AcceptConnectionFrom, tt.want)
			}
			if len(cfg.allowedSources) != len(tt.want) {
				t.Fatalf("allowedSources = %v, want %d entries", cfg.allowedSources, len(tt.want))
			}
		})
	}
}

func TestIsSourceAllowed(t *testing.T) {
	allowed, err := parseAllowedSources([]string{"192.168.1.1", "192.168.20.0/24", "::1", "::ffff:10.0.0.0/104"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		addr string
		want bool
	}{
		{addr: "192.168.1.1:5000", want: true},
		{addr: "192.168.1.2:5000", want: false},
		{addr: "192.168.20.254:5000", want: true},
		{addr: "192.168.21.1:5000", want: false},
		{addr: "[::1]:5000", want: true},
		{addr: "[::ffff:192.168.20.10]:5000", want: true},
		{addr: "10.1.2.3:5000", want: true},
		{addr: "127.0.0.1:5000", want: false},
		{addr: "[fe80::1%eth0]:5000", want: false},
	}
	for _, tt := range tests {
		addr, err := net.ResolveTCPAddr("tcp", tt.addr)
		if err != nil {
			t.Fatal(err)
		}
		if got := isSourceAllowed(addr, allowed); got != tt.want {
			t.Errorf("isSourceAllowed(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestSourceFilterListenerRejectsDisallowedSources(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	allowed, err := parseAllowedSources([]string{"192.168.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	filtered := &sourceFilterListener{Listener: ln, allowed: allowed, logger: log.New(&logs, "", 0)}

	accepted := make(chan net.Conn, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := filtered.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("read succeeded, want rejected connection to be closed")
	}
	// Closing the listener unblocks Accept, so the log buffer can be read safely.
	ln.Close()
	<-done
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("disallowed connection was accepted")
	default:
	}
	if !strings.Contains(logs.String(), "REJECTED 127.0.0.1:") {
		t.Fatalf("log = %q, want REJECTED entry", logs.String())
	}
}

func TestMatchesHost(t *testing.T) {
	blocked := []string{"facebook.com", "Ads.Example.com."}
	tests := []struct {
		host string
		want bool
	}{
		{host: "facebook.com", want: true},
		{host: "facebook.com:443", want: true},
		{host: "www.facebook.com:8080", want: true},
		{host: "FACEBOOK.COM.", want: true},
		{host: "ads.example.com", want: true},
		{host: "x.ads.example.com:80", want: true},
		{host: "notfacebook.com", want: false},
		{host: "facebook.com.evil.test", want: false},
		{host: "example.com", want: false},
		{host: "[::1]:443", want: false},
	}
	for _, tt := range tests {
		if got := matchesHost(tt.host, blocked); got != tt.want {
			t.Errorf("matchesHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

const testParentAuth = "Basic dXNlcjpwYXNz" // user:pass

// newForwardingTestProxy starts a target server, a parent proxy requiring
// user:pass and the mini proxy configured with the given credentials.
func newForwardingTestProxy(t *testing.T, username, password string) (target *httptest.Server, proxy *proxyServer, proxyURL *url.URL) {
	t.Helper()
	target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/ws":
			if r.Header.Get("Upgrade") != "websocket" {
				http.Error(w, "upgrade required", http.StatusUpgradeRequired)
				return
			}
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			rw.Flush()
			line, err := rw.ReadString('\n')
			if err != nil {
				return
			}
			rw.WriteString("echo " + line)
			rw.Flush()
		default:
			w.Header().Set("X-Seen-Proxy-Authorization", r.Header.Get("Proxy-Authorization"))
			io.WriteString(w, "ok")
		}
	}))
	t.Cleanup(target.Close)

	forward := &httputil.ReverseProxy{
		Rewrite:   func(*httputil.ProxyRequest) {},
		Transport: &http.Transport{Proxy: nil},
	}
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != testParentAuth {
			http.Error(w, "authentication required", http.StatusProxyAuthRequired)
			return
		}
		forward.ServeHTTP(w, r)
	}))
	t.Cleanup(parent.Close)

	cfg := Config{ParentProxy: parent.URL, Username: username, Password: password, StopIfAuthFail: true}
	proxy, err := newProxyServer(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.transport.CloseIdleConnections)
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	proxyURL, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return target, proxy, proxyURL
}

func TestProxyForwardsRequestsTransparently(t *testing.T) {
	target, _, proxyURL := newForwardingTestProxy(t, "user", "pass")
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	resp, err := client.Get(target.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect status = %d, want %d (redirects must reach the client)", resp.StatusCode, http.StatusFound)
	}

	req, err := http.NewRequest(http.MethodGet, target.URL+"/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", "Basic Y2xpZW50OnNlY3JldA==")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("response = %d %q, want 200 ok", resp.StatusCode, body)
	}
	if seen := resp.Header.Get("X-Seen-Proxy-Authorization"); seen != "" {
		t.Fatalf("target received Proxy-Authorization %q, want none", seen)
	}
}

func TestProxyForwardsWebSocketUpgrade(t *testing.T) {
	target, _, proxyURL := newForwardingTestProxy(t, "user", "pass")
	conn, err := net.DialTimeout("tcp", proxyURL.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	targetHost := strings.TrimPrefix(target.URL, "http://")
	fmt.Fprintf(conn, "GET http://%s/ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", targetHost, targetHost)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	io.WriteString(conn, "ping\n")
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "echo ping\n" {
		t.Fatalf("upgraded connection returned %q, want %q", line, "echo ping\n")
	}
}

func TestProxyStopsAfterParentAuthenticationFailure(t *testing.T) {
	target, proxy, proxyURL := newForwardingTestProxy(t, "user", "wrong")
	var failures atomic.Int32
	proxy.onAuthFailure = func() { failures.Add(1) }
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	defer client.CloseIdleConnections()

	for _, want := range []int{http.StatusProxyAuthRequired, http.StatusServiceUnavailable} {
		resp, err := client.Get(target.URL + "/hello")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("status = %d, want %d", resp.StatusCode, want)
		}
	}
	if got := failures.Load(); got != 1 {
		t.Fatalf("onAuthFailure called %d times, want 1", got)
	}
}

// startTunnelTestTarget runs a TCP server that echoes every line prefixed
// with "echo " and returns its address.
func startTunnelTestTarget(t *testing.T) *net.TCPAddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					fmt.Fprintf(conn, "echo %s", line)
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr)
}

func startTestTunnel(t *testing.T, target *net.TCPAddr, allowed []netip.Prefix) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := TCPTunnel{SourceAddr: listener.Addr().String(), TargetHost: target.IP.String(), TargetPort: target.Port}
	logger := log.New(io.Discard, "", 0)
	tunnel := newTCPTunnelServer(cfg, &sourceFilterListener{Listener: listener, allowed: allowed, logger: logger}, logger, false)
	go tunnel.Serve()
	t.Cleanup(tunnel.Close)
	return cfg.SourceAddr
}

func TestTCPTunnelRelaysDirectlyToTarget(t *testing.T) {
	addr := startTestTunnel(t, startTunnelTestTarget(t), []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(conn, "hello\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "echo hello\n" {
		t.Fatalf("tunnel returned %q, want %q", line, "echo hello\n")
	}
}

func TestTCPTunnelRejectsDisallowedSources(t *testing.T) {
	addr := startTestTunnel(t, startTunnelTestTarget(t), []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")})

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(conn, "hello\n")
	if _, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
		t.Fatal("connection from a disallowed source was relayed")
	}
}

func TestLoadConfigAcceptTCPConnectionFrom(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    []string
		wantErr bool
	}{
		{name: "defaults to loopback", json: `{}`, want: []string{"127.0.0.1", "::1"}},
		{name: "independent of accept_connection_from", json: `{"accept_connection_from":["10.0.0.1"]}`, want: []string{"127.0.0.1", "::1"}},
		{name: "explicit list", json: `{"accept_tcp_connection_from":["192.168.20.0/24"]}`, want: []string{"192.168.20.0/24"}},
		{name: "empty list", json: `{"accept_tcp_connection_from":[]}`, wantErr: true},
		{name: "invalid entry", json: `{"accept_tcp_connection_from":["not-an-ip"]}`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tt.json), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadConfig(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("loadConfig() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(cfg.AcceptTCPConnectionFrom, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("AcceptTCPConnectionFrom = %v, want %v", cfg.AcceptTCPConnectionFrom, tt.want)
			}
			if len(cfg.allowedTCPSources) != len(tt.want) {
				t.Fatalf("allowedTCPSources = %v, want %d entries", cfg.allowedTCPSources, len(tt.want))
			}
		})
	}
}

func TestLoadConfigTCPTunnel(t *testing.T) {
	tests := []struct {
		name    string
		tunnels string
		wantErr bool
	}{
		{name: "omitted", tunnels: ""},
		{name: "empty", tunnels: `,"tcp_tunnel":[]`},
		{name: "valid", tunnels: `,"tcp_tunnel":[{"source_addr":"127.0.0.1:2222","target_host":"10.0.0.10","target_port":22}]`},
		{name: "missing port in source", tunnels: `,"tcp_tunnel":[{"source_addr":"127.0.0.1","target_host":"10.0.0.10","target_port":22}]`, wantErr: true},
		{name: "missing target host", tunnels: `,"tcp_tunnel":[{"source_addr":":2222","target_port":22}]`, wantErr: true},
		{name: "invalid target port", tunnels: `,"tcp_tunnel":[{"source_addr":":2222","target_host":"10.0.0.10","target_port":0}]`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			data := `{"key_seed":"seed","listen_addr":":0","parent_proxy":"http://proxy.test:3128"` + tt.tunnels + `}`
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := loadConfig(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("loadConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProxyDirectWithoutParent(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/407" {
			http.Error(w, "origin 407", http.StatusProxyAuthRequired)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer target.Close()

	proxy, err := newProxyServer(Config{StopIfAuthFail: true}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.transport.CloseIdleConnections()
	server := httptest.NewServer(proxy)
	defer server.Close()
	proxyURL, _ := url.Parse(server.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	defer client.CloseIdleConnections()

	resp, err := client.Get(target.URL + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("response = %d %q, want 200 ok", resp.StatusCode, body)
	}

	// A 407 from a destination reached directly is not a parent auth failure.
	resp, err = client.Get(target.URL + "/407")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired || proxy.authFailed.Load() {
		t.Fatalf("status = %d, authFailed = %v; want 407 and the proxy still running", resp.StatusCode, proxy.authFailed.Load())
	}

	// CONNECT is tunneled directly to the destination.
	conn, err := net.DialTimeout("tcp", proxyURL.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	targetAddr := strings.TrimPrefix(target.URL, "http://")
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	reader := bufio.NewReader(conn)
	connectResp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || connectResp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response = %v, %v", connectResp, err)
	}
	fmt.Fprintf(conn, "GET /hello HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetAddr)
	tunneled, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(tunneled.Body)
	tunneled.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("tunneled body = %q, want ok", body)
	}
}

func TestProxyDetectsLoopToItself(t *testing.T) {
	proxy, err := newProxyServer(Config{}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.transport.CloseIdleConnections()
	server := httptest.NewServer(proxy)
	defer server.Close()
	proxyURL, _ := url.Parse(server.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()

	// DIRECT to the proxy's own address would forward the request forever.
	resp, err := client.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusLoopDetected {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusLoopDetected)
	}
}

func TestProxyKeepsClientForwardingHeaders(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%q %q", r.Header.Values("X-Forwarded-For"), r.Header.Values("Forwarded"))
	}))
	defer target.Close()
	proxy, err := newProxyServer(Config{}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.transport.CloseIdleConnections()
	server := httptest.NewServer(proxy)
	defer server.Close()
	proxyURL, _ := url.Parse(server.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	defer client.CloseIdleConnections()

	get := func(header http.Header) string {
		req, _ := http.NewRequest(http.MethodGet, target.URL, nil)
		req.Header = header
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}
	// The proxy adds no forwarding header of its own...
	if got := get(http.Header{}); got != `[] []` {
		t.Errorf("without client headers, target saw %s", got)
	}
	// ...and passes the client's ones unchanged.
	if got := get(http.Header{"X-Forwarded-For": {"10.1.1.1"}, "Forwarded": {"for=10.1.1.1"}}); got != `["10.1.1.1"] ["for=10.1.1.1"]` {
		t.Errorf("with client headers, target saw %s", got)
	}
}
