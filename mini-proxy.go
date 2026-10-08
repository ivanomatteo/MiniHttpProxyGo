package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"
)

// Config structure read from JSON file
type Config struct {
	ListenAddr     string   `json:"listen_addr"`       // e.g. ":3128"
	ParentProxy    string   `json:"parent_proxy"`      // e.g. "http://proxy.example.local:8080"
	Username       string   `json:"username"`          // basic auth username for parent
	Password       string   `json:"password"`          // basic auth password for parent
	LogFile        string   `json:"log_file"`          // e.g. "proxy.log"
	BlockedHosts   []string `json:"blocked_hosts"`     // hosts to block (exact or suffix)
	DirectHosts    []string `json:"direct_hosts"`      // hosts reached directly, overriding PAC and parent_proxy
	Debug          bool     `json:"debug"`             // enable debug logging (e.g. client process ID)
	StopIfAuthFail bool     `json:"stop_if_auth_fail"` // stop when the parent proxy returns HTTP 407

	// PAC script (http(s) URL or local file) that chooses the upstream per
	// request; mutually exclusive with parent_proxy.
	PACURL string `json:"pac_url"`
	// minutes between PAC reloads, 0 disables reloading
	PACRefreshMinutes int `json:"pac_refresh_minutes"`
	// source IPs or CIDR ranges allowed to connect, e.g. ["127.0.0.1", "192.168.20.0/24"]
	AcceptConnectionFrom []string `json:"accept_connection_from"`
	// TCP ports forwarded directly to a fixed destination, without the parent proxy
	TCPTunnels []TCPTunnel `json:"tcp_tunnel"`
	// source IPs or CIDR ranges allowed to connect to the TCP tunnels
	AcceptTCPConnectionFrom []string `json:"accept_tcp_connection_from"`

	allowedSources    []netip.Prefix
	allowedTCPSources []netip.Prefix
}

// TCPTunnel forwards every connection accepted on SourceAddr directly to
// TargetHost:TargetPort. It is independent of the HTTP proxy and never uses
// the parent proxy.
type TCPTunnel struct {
	SourceAddr string `json:"source_addr"` // e.g. "127.0.0.1:2222"
	TargetHost string `json:"target_host"` // e.g. "10.0.0.10"
	TargetPort int    `json:"target_port"` // e.g. 22
}

func (t TCPTunnel) target() string {
	return net.JoinHostPort(t.TargetHost, strconv.Itoa(t.TargetPort))
}

type encryptedPassword struct {
	Encrypted string `json:"encrypted"`
}

const connectTimeout = 30 * time.Second

func main() {
	cfgPath := flag.String("config", "config.json", "path to config json")
	serviceMode := flag.Bool("service", false, "run in service mode (disables interactive prompts)")
	flag.Parse()

	if err := runService(*cfgPath, *serviceMode); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func runProxy(cfgPath string, stopChan <-chan struct{}, serviceMode bool) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	readPassword := func() (string, error) {
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stdout)
		return string(password), err
	}
	if err := resolveCredentials(&cfg, serviceMode, os.Stdin, os.Stdout, readPassword); err != nil {
		return err
	}

	// setup logging
	var logOut io.Writer = os.Stdout
	var logFile *os.File
	if cfg.LogFile != "" {
		logFilePath := exeRelativePath(cfg.LogFile)
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("open log file (%s): %w", logFilePath, err)
		}
		logFile = f
		defer logFile.Close()
		logOut = f
	}
	logger := log.New(logOut, "mini-proxy: ", log.LstdFlags)

	cfg.PACURL = resolvePACPath(cfg.PACURL)
	proxy, err := newProxyServer(cfg, logger)
	if err != nil {
		return err
	}
	if proxy.pac != nil {
		pacCtx, stopPAC := context.WithCancel(context.Background())
		defer stopPAC()
		go proxy.pac.Run(pacCtx, time.Duration(cfg.PACRefreshMinutes)*time.Minute)
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
	}
	listener = &sourceFilterListener{Listener: listener, allowed: cfg.allowedSources, logger: logger}

	tunnels := make([]*tcpTunnelServer, 0, len(cfg.TCPTunnels))
	closeTunnels := func() {
		for _, tunnel := range tunnels {
			tunnel.Close()
		}
	}
	defer closeTunnels()
	for _, tunnelCfg := range cfg.TCPTunnels {
		tunnelListener, err := net.Listen("tcp", tunnelCfg.SourceAddr)
		if err != nil {
			listener.Close()
			return fmt.Errorf("tcp_tunnel: listen on %s: %w", tunnelCfg.SourceAddr, err)
		}
		tunnels = append(tunnels, newTCPTunnelServer(tunnelCfg,
			&sourceFilterListener{Listener: tunnelListener, allowed: cfg.allowedTCPSources, logger: logger},
			logger, cfg.Debug))
	}

	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: proxy,
		// Only bounds reading request headers: tunnels and upgraded connections
		// are hijacked and are not affected.
		ReadHeaderTimeout: connectTimeout,
		IdleTimeout:       2 * time.Minute,
	}
	proxy.onAuthFailure = func() {
		message := "ERROR parent proxy rejected credentials or requires authentication; stopping proxy"
		logger.Print(message)
		if logFile != nil {
			fmt.Fprintf(os.Stdout, "mini-proxy: %s\n", message)
		}
		proxy.transport.CloseIdleConnections()
		go func() {
			// Shutdown lets the request that received the 407 deliver its response
			// before the connection is closed; new connections are refused at once.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := httpServer.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
				httpServer.Close()
				logger.Printf("FAILED stopping server gracefully after parent authentication error: %v", err)
			}
		}()
	}

	stopped := make(chan struct{})
	go func() {
		<-stopChan
		close(stopped)
		logger.Printf("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(ctx)
	}()

	logger.Printf("Starting mini proxy on %s, forwarding %s, accepting connections from %s",
		cfg.ListenAddr, proxy.describeRouting(), strings.Join(cfg.AcceptConnectionFrom, ", "))
	for _, tunnel := range tunnels {
		logger.Printf("Starting TCP tunnel on %s, forwarding directly to %s, accepting connections from %s",
			tunnel.cfg.SourceAddr, tunnel.cfg.target(), strings.Join(cfg.AcceptTCPConnectionFrom, ", "))
		go tunnel.Serve()
	}
	if err := httpServer.Serve(listener); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	// TCP tunnels do not use the parent proxy, so a parent authentication
	// failure leaves them running until the service is stopped.
	if proxy.authFailed.Load() && len(tunnels) > 0 {
		logger.Printf("HTTP proxy stopped; TCP tunnels keep running until shutdown")
		<-stopped
	}
	return nil
}

// exeRelativePath resolves a relative path against the executable directory,
// so that it does not depend on the working directory of a service.
func exeRelativePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	exePath, err := os.Executable()
	if err != nil {
		return path
	}
	return filepath.Join(filepath.Dir(exePath), path)
}

// resolvePACPath resolves a local pac_url like log_file; URLs are unchanged.
func resolvePACPath(src string) string {
	if src == "" || strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return src
	}
	return exeRelativePath(strings.TrimPrefix(src, "file://"))
}

// proxyServer forwards plain HTTP requests (including ws:// upgrades) and
// tunnels CONNECT requests, directly or through the upstream chosen by route.
type proxyServer struct {
	cfg       Config
	parentURL *url.URL // nil when parent_proxy is not configured
	proxyAuth string   // Proxy-Authorization value for the parent, empty when disabled
	transport *http.Transport
	logger    *log.Logger
	pac       *pacManager // nil when pac_url is not configured
	// local addresses of the connections this proxy opened, to detect
	// requests that loop back to the proxy itself
	ownConns sync.Map

	authFailed    atomic.Bool
	onAuthFailure func() // called once when the parent rejects the credentials
}

func newProxyServer(cfg Config, logger *log.Logger) (*proxyServer, error) {
	if cfg.ParentProxy != "" && cfg.PACURL != "" {
		return nil, errors.New("parent_proxy and pac_url are mutually exclusive: set only one of them")
	}
	var parentURL *url.URL
	// Without parent_proxy and pac_url every request goes DIRECT.
	if cfg.ParentProxy != "" {
		var err error
		parentURL, err = url.Parse(cfg.ParentProxy)
		if err != nil {
			return nil, fmt.Errorf("invalid parent_proxy: %w", err)
		}
		if parentURL.Scheme != "http" && parentURL.Scheme != "https" {
			return nil, fmt.Errorf("invalid parent_proxy: unsupported scheme %q", parentURL.Scheme)
		}
	}

	proxyAuth := ""
	if cfg.Username != "" || cfg.Password != "" {
		b := cfg.Username + ":" + cfg.Password
		proxyAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(b))
	}

	p := &proxyServer{
		cfg:       cfg,
		parentURL: parentURL,
		proxyAuth: proxyAuth,
		logger:    logger,
	}

	if cfg.PACURL != "" {
		pac, err := newPACManager(cfg.PACURL, logger)
		if err != nil {
			return nil, fmt.Errorf("pac_url: %w", err)
		}
		p.pac = pac
	}

	// transport that picks the upstream per request
	p.transport = &http.Transport{
		Proxy:               p.transportProxy,
		DialContext:         p.dialTracked,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   false,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		// Pass bodies through unchanged instead of negotiating gzip on behalf of
		// the client.
		DisableCompression: true,
		// Plain HTTP requests for every destination share the connections to the
		// parent proxy, so keep more than the default two idle.
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
	}
	return p, nil
}

// dialTracked dials like a plain dialer and records the local address of the
// connection until it is closed. A request arriving from one of these
// addresses was sent by this proxy to itself (e.g. a request for the proxy's
// own address while connecting DIRECT) and would loop forever.
func (p *proxyServer) dialTracked(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	key := conn.LocalAddr().String()
	p.ownConns.Store(key, struct{}{})
	return &trackedConn{Conn: conn, release: func() { p.ownConns.Delete(key) }}, nil
}

func (p *proxyServer) isOwnConn(remoteAddr string) bool {
	_, ok := p.ownConns.Load(remoteAddr)
	return ok
}

type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// CloseWrite keeps the half-close used by relayTunnel.
func (c *trackedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// withAuth returns a copy of u carrying the configured parent credentials.
// The transport derives Proxy-Authorization from the proxy URL, both for
// forwarded requests and for CONNECT to https:// targets.
func (p *proxyServer) withAuth(u *url.URL) *url.URL {
	if u == nil || p.proxyAuth == "" {
		return u
	}
	c := *u
	c.User = url.UserPassword(p.cfg.Username, p.cfg.Password)
	return &c
}

// describeRouting summarizes, for the startup log, where requests are sent.
func (p *proxyServer) describeRouting() string {
	switch {
	case p.pac != nil:
		src := p.cfg.PACURL
		if u, err := url.Parse(src); err == nil && u.Host != "" {
			src = u.Redacted()
		}
		return "as chosen by PAC " + src
	case p.parentURL != nil:
		return "to " + p.parentURL.Redacted()
	default:
		return "directly"
	}
}

// route returns the ordered upstreams for a request, by priority:
// direct_hosts, then the PAC or parent_proxy (mutually exclusive), then DIRECT
// when neither is configured. A PAC failure is an error, not a silent DIRECT:
// connecting directly is a policy decision.
func (p *proxyServer) route(rawURL, host string) ([]pacRoute, error) {
	if matchesHost(host, p.cfg.DirectHosts) {
		return []pacRoute{{Direct: true}}, nil
	}
	if p.pac != nil {
		return p.pac.FindProxy(rawURL, host)
	}
	if p.parentURL == nil {
		return []pacRoute{{Direct: true}}, nil
	}
	return []pacRoute{{Proxy: p.parentURL}}, nil
}

// routeKey carries the route being tried to transportProxy, so the PAC is
// evaluated once per request.
type routeKey struct{}

// transportProxy is http.Transport.Proxy. It uses the route that
// roundTripRoutes is trying, or the first route when none is set.
func (p *proxyServer) transportProxy(req *http.Request) (*url.URL, error) {
	route, ok := req.Context().Value(routeKey{}).(pacRoute)
	if !ok {
		routes, err := p.route(req.URL.String(), req.URL.Hostname())
		if err != nil {
			return nil, err
		}
		route = routes[0]
	}
	if route.Direct {
		return nil, nil
	}
	return p.withAuth(route.Proxy), nil
}

func (p *proxyServer) parentAuthenticationFailed() {
	if !p.cfg.StopIfAuthFail {
		return
	}
	if p.authFailed.CompareAndSwap(false, true) && p.onAuthFailure != nil {
		p.onAuthFailure()
	}
}

func (p *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.authFailed.Load() {
		http.Error(w, "Proxy stopped: parent proxy authentication failed", http.StatusServiceUnavailable)
		return
	}
	start := time.Now()
	clientIP := r.RemoteAddr
	targetHost := r.Host

	if p.isOwnConn(clientIP) {
		p.logger.Printf("LOOP %s %s %s: request sent by this proxy to itself", clientIP, r.Method, r.URL.String())
		http.Error(w, "Loop detected: the request targets this proxy", http.StatusLoopDetected)
		return
	}

	procInfo := ""
	if p.cfg.Debug {
		procInfo = identifyProcess(clientIP)
		if procInfo != "" {
			procInfo = " [" + procInfo + "]"
		}
	}

	// check blacklist: it has priority over direct_hosts and the PAC
	if matchesHost(targetHost, p.cfg.BlockedHosts) {
		p.logger.Printf("BLOCKED %s%s %s %s -> %s", clientIP, procInfo, r.Method, r.URL.String(), targetHost)
		http.Error(w, "Forbidden by proxy (blocked)", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodConnect {
		if err := p.handleConnect(w, r); err != nil {
			p.logger.Printf("FAILED CONNECT %s%s %s -> %v", clientIP, procInfo, r.Host, err)
			if errors.Is(err, errParentProxyAuthentication) {
				p.parentAuthenticationFailed()
			}
		} else {
			p.logger.Printf("TUNNELED %s%s %s %s in %s", clientIP, procInfo, r.Method, r.Host, time.Since(start))
		}
		return
	}

	outURL := *r.URL
	if !outURL.IsAbs() {
		outURL.Scheme = "http"
		outURL.Host = r.Host
	}
	routes, err := p.route(outURL.String(), outURL.Hostname())
	if err != nil {
		p.logger.Printf("FAILED %s%s %s %s -> %v", clientIP, procInfo, r.Method, r.URL.String(), err)
		http.Error(w, "Bad Gateway: cannot choose an upstream", http.StatusBadGateway)
		return
	}

	var proxyErr error
	status := 0
	var used pacRoute // the route that produced the response
	forwarder := &httputil.ReverseProxy{
		Transport: roundTripperFunc(func(out *http.Request) (*http.Response, error) {
			resp, route, err := p.roundTripRoutes(out, routes)
			used = route
			return resp, err
		}),
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = outURL.Scheme
			pr.Out.URL.Host = outURL.Host
			// Rewrite drops the forwarding headers and adds none: pass on the
			// client's own unchanged, without adding the client address.
			for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
				if values, ok := pr.In.Header[name]; ok {
					pr.Out.Header[name] = values
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			status = resp.StatusCode
			// Only a proxy's 407 means the configured credentials were rejected.
			if resp.StatusCode == http.StatusProxyAuthRequired && !used.Direct {
				p.parentAuthenticationFailed()
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			proxyErr = err
			w.WriteHeader(http.StatusBadGateway)
		},
		ErrorLog: p.logger,
	}
	forwarder.ServeHTTP(w, r)

	if proxyErr != nil {
		p.logger.Printf("FAILED %s%s %s %s -> %v", clientIP, procInfo, r.Method, r.URL.String(), proxyErr)
		return
	}
	p.logger.Printf("PROXIED %s%s %s %s -> %d in %s", clientIP, procInfo, r.Method, r.URL.String(), status, time.Since(start))
}

// roundTripRoutes sends req through the routes in order, moving to the next
// one only when the connection could not be established: the request has not
// been sent yet, so retrying it is safe. A response (including a 407) or a
// later error ends the walk, as for CONNECT.
func (p *proxyServer) roundTripRoutes(req *http.Request, routes []pacRoute) (*http.Response, pacRoute, error) {
	// The transport closes the body on errors; keep it open for the next route.
	// The server closes the incoming body once the handler returns.
	var body *retryBody
	if req.Body != nil && req.Body != http.NoBody {
		body = &retryBody{ReadCloser: req.Body}
		req.Body = body
	}
	for i, route := range routes {
		out := req.WithContext(context.WithValue(req.Context(), routeKey{}, route))
		resp, err := p.transport.RoundTrip(out)
		if err == nil {
			if p.cfg.Debug {
				p.logger.Printf("ROUTE %s %s via %s", req.Method, req.URL.Redacted(), route)
			}
			return resp, route, nil
		}
		if !isDialError(err) || (body != nil && body.read) || i == len(routes)-1 {
			return nil, route, err
		}
		p.logger.Printf("FAILED route %s %s via %s: %v", req.Method, req.URL.Redacted(), route, err)
	}
	return nil, pacRoute{}, errors.New("no route") // unreachable: route never returns an empty list
}

// isDialError reports whether err happened while connecting, directly or to a
// proxy, before anything of the request was sent.
func isDialError(err error) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		if op, ok := err.(*net.OpError); ok && op.Op == "dial" {
			return true
		}
	}
	return false
}

// retryBody ignores Close, so a request body survives a failed attempt, and
// records whether any byte was consumed (then the request cannot be retried).
type retryBody struct {
	io.ReadCloser
	read bool
}

func (b *retryBody) Read(buf []byte) (int, error) {
	n, err := b.ReadCloser.Read(buf)
	if n > 0 {
		b.read = true
	}
	return n, err
}

func (b *retryBody) Close() error { return nil }

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func loadConfig(cfgPath string) (Config, error) {
	cfg := Config{
		StopIfAuthFail:          true,
		PACRefreshMinutes:       60,
		AcceptConnectionFrom:    []string{"127.0.0.1", "::1"},
		AcceptTCPConnectionFrom: []string{"127.0.0.1", "::1"},
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return cfg, fmt.Errorf("open config: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}

	seed := ""
	seedAdded := false
	if seedJSON, ok := raw["key_seed"]; ok {
		if err := json.Unmarshal(seedJSON, &seed); err != nil || seed == "" {
			return cfg, fmt.Errorf("key_seed must be a non-empty string")
		}
	} else {
		seed, err = randomSeed(20)
		if err != nil {
			return cfg, fmt.Errorf("generate key_seed: %w", err)
		}
		raw["key_seed"], _ = json.Marshal(seed)
		seedAdded = true
	}

	passwordJSON, hasPassword := raw["password"]
	if !hasPassword {
		passwordJSON = json.RawMessage(`""`)
	}
	var plainPassword string
	if err := json.Unmarshal(passwordJSON, &plainPassword); err != nil {
		var encrypted encryptedPassword
		if objectErr := json.Unmarshal(passwordJSON, &encrypted); objectErr != nil || encrypted.Encrypted == "" {
			return cfg, fmt.Errorf("password must be a string or an object containing encrypted")
		}
		username, err := configUsername(raw)
		if err != nil {
			return cfg, err
		}
		plainPassword, err = decryptPassword(encrypted.Encrypted, seed, username)
		if err != nil {
			return cfg, fmt.Errorf("decrypt password: %w", err)
		}
	}

	configForDecode := make(map[string]json.RawMessage, len(raw))
	maps.Copy(configForDecode, raw)
	configForDecode["password"], _ = json.Marshal(plainPassword)
	decodeData, _ := json.Marshal(configForDecode)
	if err := json.Unmarshal(decodeData, &cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}

	cfg.allowedSources, err = parseAllowedSources(cfg.AcceptConnectionFrom)
	if err != nil {
		return cfg, fmt.Errorf("accept_connection_from: %w", err)
	}
	cfg.allowedTCPSources, err = parseAllowedSources(cfg.AcceptTCPConnectionFrom)
	if err != nil {
		return cfg, fmt.Errorf("accept_tcp_connection_from: %w", err)
	}
	if err := validateTCPTunnels(cfg.TCPTunnels); err != nil {
		return cfg, fmt.Errorf("tcp_tunnel: %w", err)
	}

	needsWrite := seedAdded
	// Empty and [ask] are control values, not secrets.
	if plainPassword != "" && plainPassword != "[ask]" {
		if passwordJSON[0] == '"' {
			encoded, err := encryptPassword(plainPassword, seed, cfg.Username)
			if err != nil {
				return cfg, fmt.Errorf("encrypt password: %w", err)
			}
			raw["password"], _ = json.Marshal(encryptedPassword{Encrypted: encoded})
			needsWrite = true
		}
	}
	if needsWrite {
		if err := writeConfig(cfgPath, raw); err != nil {
			return cfg, fmt.Errorf("update config: %w", err)
		}
	}
	return cfg, nil
}

func configUsername(raw map[string]json.RawMessage) (string, error) {
	var username string
	if value, ok := raw["username"]; ok {
		if err := json.Unmarshal(value, &username); err != nil {
			return "", fmt.Errorf("username must be a string")
		}
	}
	return username, nil
}

func randomSeed(length int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	random := make([]byte, length)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	for i, value := range random {
		result[i] = alphabet[int(value)%len(alphabet)]
	}
	return string(result), nil
}

func passwordKey(seed, username string) []byte {
	seedHash := sha1.Sum([]byte(seed))
	material := append(seedHash[:], []byte(username)...)
	keyHash := sha1.Sum(material)
	return keyHash[:aes.BlockSize]
}

func encryptPassword(password, seed, username string) (string, error) {
	gcm, err := passwordCipher(seed, username)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(password), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func decryptPassword(encoded, seed, username string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("invalid base64: %w", err)
	}
	gcm, err := passwordCipher(seed, username)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("encrypted value is too short")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("invalid key or encrypted value")
	}
	return string(plain), nil
}

func passwordCipher(seed, username string) (cipher.AEAD, error) {
	block, err := aes.NewCipher(passwordKey(seed, username))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func writeConfig(path string, raw map[string]json.RawMessage) error {
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mini-proxy-config-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func resolveCredentials(cfg *Config, serviceMode bool, input io.Reader, output io.Writer, readPassword func() (string, error)) error {
	const ask = "[ask]"
	if cfg.Username != ask && cfg.Password != ask {
		return nil
	}
	if serviceMode {
		return fmt.Errorf("username/password cannot be %q in service mode", ask)
	}

	reader := bufio.NewReader(input)
	readValue := func(prompt string) (string, error) {
		if _, err := fmt.Fprint(output, prompt); err != nil {
			return "", err
		}
		value, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		if err == io.EOF && value == "" {
			return "", fmt.Errorf("no value entered")
		}
		return strings.TrimRight(value, "\r\n"), nil
	}

	var err error
	if cfg.Username == ask {
		cfg.Username, err = readValue("Parent proxy username: ")
		if err != nil {
			return fmt.Errorf("read username: %w", err)
		}
	}
	if cfg.Password == ask {
		if _, err := fmt.Fprint(output, "Parent proxy password: "); err != nil {
			return fmt.Errorf("write password prompt: %w", err)
		}
		cfg.Password, err = readPassword()
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
	}
	return nil
}

// parseAllowedSources converts IP addresses and CIDR ranges into prefixes.
// A single IP is treated as a host prefix (/32 for IPv4, /128 for IPv6).
func parseAllowedSources(entries []string) ([]netip.Prefix, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("at least one IP address or CIDR range is required")
	}
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR range %q", entry)
			}
			if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address %q", entry)
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

func isSourceAllowed(remoteAddr net.Addr, allowed []netip.Prefix) bool {
	addrPort, err := netip.ParseAddrPort(remoteAddr.String())
	if err != nil {
		return false
	}
	// IPv4 clients on a dual-stack listener appear as ::ffff:a.b.c.d.
	addr := addrPort.Addr().Unmap().WithZone("")
	for _, prefix := range allowed {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// sourceFilterListener closes connections whose source IP is not allowed
// before any request data is read.
type sourceFilterListener struct {
	net.Listener
	allowed []netip.Prefix
	logger  *log.Logger
}

func (l *sourceFilterListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if isSourceAllowed(conn.RemoteAddr(), l.allowed) {
			return conn, nil
		}
		l.logger.Printf("REJECTED %s: source address not allowed", conn.RemoteAddr())
		conn.Close()
	}
}

// matchesHost reports whether host (optionally with a port) equals an entry
// of list or is a subdomain of it. Used for blocked_hosts and direct_hosts.
func matchesHost(host string, list []string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, b := range list {
		bb := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(b)), ".")
		if bb == "" {
			continue
		}
		if host == bb || strings.HasSuffix(host, "."+bb) {
			return true
		}
	}
	return false
}

var errParentProxyAuthentication = errors.New("parent proxy authentication required or rejected")

var errParentConnectRefused = errors.New("parent proxy refused CONNECT")

// handleConnect tunnels r.Host through the upstream chosen by route.
func (p *proxyServer) handleConnect(w http.ResponseWriter, r *http.Request) error {
	upConn, upReader, err := p.dialConnectUpstream(r.Host)
	return finishConnect(w, upConn, upReader, err, p.logger)
}

// dialConnectUpstream walks the routes in order until one gives a tunnel to
// target. A proxy that answers the CONNECT with an error (407 included) stops
// the walk, as for plain HTTP: only connection failures move to the next route.
func (p *proxyServer) dialConnectUpstream(target string) (net.Conn, *bufio.Reader, error) {
	routes, err := p.route(connectPACURL(target))
	if err != nil {
		return nil, nil, err
	}
	var lastErr error
	for _, route := range routes {
		var conn net.Conn
		var reader *bufio.Reader
		if route.Direct {
			conn, err = p.dialTracked(context.Background(), "tcp", target)
			if err == nil {
				reader = bufio.NewReader(conn)
			}
		} else {
			conn, reader, err = connectThroughParent(route.Proxy, p.proxyAuth, target)
		}
		if err == nil {
			if p.cfg.Debug {
				p.logger.Printf("ROUTE CONNECT %s via %s", target, route)
			}
			return conn, reader, nil
		}
		if errors.Is(err, errParentProxyAuthentication) || errors.Is(err, errParentConnectRefused) {
			return nil, nil, err
		}
		p.logger.Printf("FAILED route CONNECT %s via %s: %v", target, route, err)
		lastErr = err
	}
	return nil, nil, lastErr
}

// connectPACURL returns the URL and host a PAC receives for a CONNECT to
// target: like browsers, https://host/ with the port only when it is not 443.
func connectPACURL(target string) (rawURL, host string) {
	h, port, err := net.SplitHostPort(target)
	if err != nil {
		return "https://" + target + "/", target
	}
	u := url.URL{Scheme: "https", Host: target, Path: "/"}
	if port == "443" {
		u.Host = h
		if strings.Contains(h, ":") {
			u.Host = "[" + h + "]"
		}
	}
	return u.String(), h
}

// finishConnect answers the client once the upstream tunnel is (or is not)
// ready, then relays the traffic.
func finishConnect(w http.ResponseWriter, upConn net.Conn, upReader *bufio.Reader, err error, logger *log.Logger) error {
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		switch {
		case errors.Is(err, errParentProxyAuthentication):
			w.Write([]byte("Parent proxy authentication failed\n"))
		case errors.Is(err, errParentConnectRefused):
			w.Write([]byte("Parent proxy refused CONNECT\n"))
		default:
			w.Write([]byte("Bad Gateway\n"))
		}
		return err
	}
	defer upConn.Close()

	// Hijack client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return fmt.Errorf("hijack not supported")
	}
	clientConn, clientRW, err := hj.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed", http.StatusInternalServerError)
		return fmt.Errorf("hijack: %w", err)
	}
	defer clientConn.Close()

	// write 200 OK to client to signify tunnel established
	if _, err := clientRW.WriteString("HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return fmt.Errorf("write 200 to client: %w", err)
	}
	if err := clientRW.Flush(); err != nil {
		return fmt.Errorf("flush 200 to client: %w", err)
	}

	// clientRW.Reader and upReader preserve bytes which were read ahead while
	// parsing CONNECT. Dropping either buffer can lose a TLS ClientHello or the
	// first bytes returned by the destination.
	return relayTunnel(clientConn, clientRW.Reader, upConn, upReader, logger)
}

// connectThroughParent opens a CONNECT tunnel to target on the parent proxy.
// The returned reader holds any tunneled bytes that arrived together with the
// CONNECT response and must be used to read from the connection.
func connectThroughParent(parent *url.URL, proxyAuth, target string) (net.Conn, *bufio.Reader, error) {
	upConn, err := dialParentProxy(parent)
	if err != nil {
		return nil, nil, fmt.Errorf("dial parent: %w", err)
	}
	fail := func(err error) (net.Conn, *bufio.Reader, error) {
		upConn.Close()
		return nil, nil, err
	}
	if err := upConn.SetDeadline(time.Now().Add(connectTimeout)); err != nil {
		return fail(fmt.Errorf("set parent CONNECT deadline: %w", err))
	}

	// send CONNECT request to parent
	reqLines := []string{fmt.Sprintf("CONNECT %s HTTP/1.1", target), fmt.Sprintf("Host: %s", target)}
	if proxyAuth != "" {
		reqLines = append(reqLines, fmt.Sprintf("Proxy-Authorization: %s", proxyAuth))
	}
	reqLines = append(reqLines, "\r\n")
	connectReq := strings.Join(reqLines, "\r\n")
	if _, err := upConn.Write([]byte(connectReq)); err != nil {
		return fail(fmt.Errorf("write CONNECT to parent: %w", err))
	}

	// Parse the complete HTTP response without consuming any bytes belonging to
	// the tunneled connection that may already have arrived after its headers.
	upReader := bufio.NewReader(upConn)
	connectResponse, err := http.ReadResponse(upReader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fail(fmt.Errorf("read CONNECT response: %w", err))
	}
	if connectResponse.StatusCode == http.StatusProxyAuthRequired {
		connectResponse.Body.Close()
		return fail(fmt.Errorf("%w: %s", errParentProxyAuthentication, connectResponse.Status))
	}
	if connectResponse.StatusCode < 200 || connectResponse.StatusCode >= 300 {
		connectResponse.Body.Close()
		return fail(fmt.Errorf("%w: %s", errParentConnectRefused, connectResponse.Status))
	}
	if err := upConn.SetDeadline(time.Time{}); err != nil {
		return fail(fmt.Errorf("clear parent CONNECT deadline: %w", err))
	}
	return upConn, upReader, nil
}

func dialParentProxy(parent *url.URL) (net.Conn, error) {
	parentAddr := parent.Host
	if _, _, err := net.SplitHostPort(parentAddr); err != nil {
		defaultPort := "80"
		if parent.Scheme == "https" {
			defaultPort = "443"
		}
		parentAddr = net.JoinHostPort(parent.Hostname(), defaultPort)
	}

	dialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}
	switch parent.Scheme {
	case "http":
		return dialer.Dial("tcp", parentAddr)
	case "https":
		return tls.DialWithDialer(dialer, "tcp", parentAddr, &tls.Config{
			ServerName:         parent.Hostname(),
			InsecureSkipVerify: true, // Matches the HTTP transport used by this proxy.
		})
	default:
		return nil, fmt.Errorf("unsupported parent proxy scheme %q", parent.Scheme)
	}
}

func relayTunnel(clientConn net.Conn, clientReader io.Reader, upConn net.Conn, upReader io.Reader, logger *log.Logger) error {
	type copyResult struct {
		direction string
		err       error
	}
	results := make(chan copyResult, 2)
	copyStream := func(direction string, dst net.Conn, src io.Reader) {
		_, err := io.Copy(dst, src)
		if closeWriter, ok := dst.(interface{ CloseWrite() error }); ok {
			// Best effort: preserve half-close semantics without turning a normal
			// peer shutdown into a tunnel failure.
			_ = closeWriter.CloseWrite()
		}
		results <- copyResult{direction: direction, err: err}
	}

	go copyStream("client to parent", upConn, clientReader)
	go copyStream("parent to client", clientConn, upReader)

	first := <-results
	if first.err != nil && !errors.Is(first.err, net.ErrClosed) {
		clientConn.Close()
		upConn.Close()
	}
	second := <-results

	for _, result := range []copyResult{first, second} {
		if result.err != nil && !errors.Is(result.err, net.ErrClosed) {
			logger.Printf("FAILED tunnel copy %s: %v", result.direction, result.err)
			return fmt.Errorf("copy %s: %w", result.direction, result.err)
		}
	}
	return nil
}

func parentConnectStatusError(statusLine string) error {
	if strings.HasPrefix(statusLine, "HTTP/") && strings.Contains(statusLine, " 407 ") {
		return fmt.Errorf("%w: %s", errParentProxyAuthentication, statusLine)
	}
	return nil
}

func validateTCPTunnels(tunnels []TCPTunnel) error {
	for i, tunnel := range tunnels {
		if _, _, err := net.SplitHostPort(tunnel.SourceAddr); err != nil {
			return fmt.Errorf("entry %d: invalid source_addr %q: %v", i, tunnel.SourceAddr, err)
		}
		if strings.TrimSpace(tunnel.TargetHost) == "" {
			return fmt.Errorf("entry %d: target_host is required", i)
		}
		if tunnel.TargetPort < 1 || tunnel.TargetPort > 65535 {
			return fmt.Errorf("entry %d: target_port %d out of range 1-65535", i, tunnel.TargetPort)
		}
	}
	return nil
}

// tcpTunnelServer accepts connections on a local address and relays each one
// directly to a fixed target.
type tcpTunnelServer struct {
	cfg      TCPTunnel
	listener net.Listener
	logger   *log.Logger
	debug    bool

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
}

func newTCPTunnelServer(cfg TCPTunnel, listener net.Listener, logger *log.Logger, debug bool) *tcpTunnelServer {
	return &tcpTunnelServer{cfg: cfg, listener: listener, logger: logger, debug: debug, conns: make(map[net.Conn]struct{})}
}

func (t *tcpTunnelServer) Serve() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				t.logger.Printf("FAILED accepting TCP tunnel connection on %s: %v", t.cfg.SourceAddr, err)
			}
			return
		}
		if !t.track(conn) {
			conn.Close()
			return
		}
		go func() {
			defer t.untrack(conn)
			t.handle(conn)
		}()
	}
}

// Close stops accepting connections and closes the active ones.
func (t *tcpTunnelServer) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	t.listener.Close()
	for conn := range t.conns {
		conn.Close()
	}
}

func (t *tcpTunnelServer) track(conn net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.conns[conn] = struct{}{}
	return true
}

func (t *tcpTunnelServer) untrack(conn net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.conns, conn)
	conn.Close()
}

func (t *tcpTunnelServer) handle(clientConn net.Conn) {
	start := time.Now()
	clientIP := clientConn.RemoteAddr().String()
	target := t.cfg.target()

	procInfo := ""
	if t.debug {
		procInfo = identifyProcess(clientIP)
		if procInfo != "" {
			procInfo = " [" + procInfo + "]"
		}
	}

	dialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}
	upConn, err := dialer.Dial("tcp", target)
	if err != nil {
		t.logger.Printf("FAILED TCP tunnel %s%s %s -> %s: %v", clientIP, procInfo, t.cfg.SourceAddr, target, err)
		return
	}
	if !t.track(upConn) {
		upConn.Close()
		return
	}
	defer t.untrack(upConn)

	if err := relayTunnel(clientConn, clientConn, upConn, upConn, t.logger); err != nil {
		t.logger.Printf("FAILED TCP tunnel %s%s %s -> %s: %v", clientIP, procInfo, t.cfg.SourceAddr, target, err)
		return
	}
	t.logger.Printf("TUNNELED %s%s TCP %s -> %s in %s", clientIP, procInfo, t.cfg.SourceAddr, target, time.Since(start))
}
