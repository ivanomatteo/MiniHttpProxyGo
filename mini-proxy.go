package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config structure read from JSON file
type Config struct {
	ListenAddr   string   `json:"listen_addr"`    // e.g. ":3128"
	ParentProxy  string   `json:"parent_proxy"`   // e.g. "http://proxy.example.local:8080"
	Username     string   `json:"username"`       // basic auth username for parent
	Password     string   `json:"password"`       // basic auth password for parent
	LogFile      string   `json:"log_file"`       // e.g. "proxy.log"
	BlockedHosts []string `json:"blocked_hosts"` // hosts to block (exact or suffix)
	TimeoutSec   int      `json:"timeout_sec"`   // transport timeout
	Debug        bool     `json:"debug"`         // enable debug logging (e.g. client process ID)
}

func main() {
	cfgPath := flag.String("config", "config.json", "path to config json")
	flag.Parse()

	if err := runService(*cfgPath); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func runProxy(cfgPath string, stopChan <-chan struct{}) error {
	cfgF, err := os.Open(cfgPath)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	defer cfgF.Close()

	var cfg Config
	dec := json.NewDecoder(cfgF)
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}

	// setup logging
	var logOut io.Writer = os.Stdout
	if cfg.LogFile != "" {
		logFilePath := cfg.LogFile
		if !filepath.IsAbs(logFilePath) {
			exePath, err := os.Executable()
			if err == nil {
				logFilePath = filepath.Join(filepath.Dir(exePath), logFilePath)
			}
		}
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("open log file (%s): %w", logFilePath, err)
		}
		logOut = f
	}
	logger := log.New(logOut, "mini-proxy: ", log.LstdFlags)

	// parent proxy URL
	parentURL, err := url.Parse(cfg.ParentProxy)
	if err != nil {
		return fmt.Errorf("invalid parent_proxy: %w", err)
	}

	// prepare basic auth header value for Proxy-Authorization
	proxyAuth := ""
	if cfg.Username != "" || cfg.Password != "" {
		b := cfg.Username + ":" + cfg.Password
		proxyAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(b))
	}

	if cfg.TimeoutSec == 0 {
		cfg.TimeoutSec = 30
	}

	// transport that uses the parent proxy
	transport := &http.Transport{
		Proxy: http.ProxyURL(parentURL),
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(cfg.TimeoutSec) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   false,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.TimeoutSec) * time.Second,
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		clientIP := r.RemoteAddr
		targetHost := r.Host

		procInfo := ""
		if cfg.Debug {
			procInfo = identifyProcess(clientIP)
			if procInfo != "" {
				procInfo = " [" + procInfo + "]"
			}
		}

		// check blacklist
		if isBlocked(targetHost, cfg.BlockedHosts) {
			logger.Printf("BLOCKED %s%s %s %s -> %s", clientIP, procInfo, r.Method, r.URL.String(), targetHost)
			http.Error(w, "Forbidden by proxy (blocked)", http.StatusForbidden)
			return
		}

		if r.Method == http.MethodConnect {
			if err := handleConnect(w, r, parentURL, proxyAuth, logger); err != nil {
				logger.Printf("FAILED CONNECT %s%s %s -> %v", clientIP, procInfo, r.Host, err)
			}
			logger.Printf("TUNNELED %s%s %s %s in %s", clientIP, procInfo, r.Method, r.Host, time.Since(start))
			return
		}

		reqOut := r.Clone(context.Background())
		reqOut.RequestURI = ""
		if !reqOut.URL.IsAbs() {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			reqOut.URL.Scheme = scheme
			reqOut.URL.Host = r.Host
		}

		if proxyAuth != "" {
			reqOut.Header = cloneHeader(r.Header)
			reqOut.Header.Set("Proxy-Authorization", proxyAuth)
		} else {
			reqOut.Header = cloneHeader(r.Header)
		}

		resp, err := client.Do(reqOut)
		if err != nil {
			logger.Printf("FAILED %s %s %s -> %v", clientIP, r.Method, r.URL.String(), err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			logger.Printf("FAILED copy back %s %s -> %v", clientIP, r.URL.String(), err)
		}
		logger.Printf("PROXIED %s%s %s %s -> %d in %s", clientIP, procInfo, r.Method, r.URL.String(), resp.StatusCode, time.Since(start))
	}

	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: http.HandlerFunc(handler),
	}

	go func() {
		<-stopChan
		logger.Printf("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(ctx)
	}()

	logger.Printf("Starting mini proxy on %s, forwarding to %s", cfg.ListenAddr, cfg.ParentProxy)
	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

func isBlocked(host string, blocked []string) bool {
	host = strings.ToLower(host)
	for _, b := range blocked {
		bb := strings.ToLower(strings.TrimSpace(b))
		if bb == "" {
			continue
		}
		if host == bb || strings.HasSuffix(host, "."+bb) || strings.HasSuffix(host, bb) {
			return true
		}
	}
	return false
}

func cloneHeader(h http.Header) http.Header {
	nh := make(http.Header)
	for k, vv := range h {
		for _, v := range vv {
			nh.Add(k, v)
		}
	}
	return nh
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// handleConnect sends a CONNECT to the parent proxy (with Proxy-Authorization if provided) and then tunnels the TCP streams.
func handleConnect(w http.ResponseWriter, r *http.Request, parent *url.URL, proxyAuth string, logger *log.Logger) error {
	// dial to parent proxy
	parentAddr := parent.Host
	if !strings.Contains(parentAddr, ":") {
		if parent.Scheme == "https" {
			parentAddr = parentAddr + ":443"
		} else {
			parentAddr = parentAddr + ":80"
		}
	}

	upConn, err := net.DialTimeout("tcp", parentAddr, 30*time.Second)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return fmt.Errorf("dial parent: %w", err)
	}

	// send CONNECT request to parent
	target := r.Host
	reqLines := []string{fmt.Sprintf("CONNECT %s HTTP/1.1", target), fmt.Sprintf("Host: %s", target)}
	if proxyAuth != "" {
		reqLines = append(reqLines, fmt.Sprintf("Proxy-Authorization: %s", proxyAuth))
	}
	reqLines = append(reqLines, "\r\n")
	connectReq := strings.Join(reqLines, "\r\n")
	if _, err := upConn.Write([]byte(connectReq)); err != nil {
		upConn.Close()
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return fmt.Errorf("write CONNECT to parent: %w", err)
	}

	// read response status line from parent
	br := make([]byte, 4096)
	n, err := upConn.Read(br)
	if err != nil {
		upConn.Close()
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return fmt.Errorf("read CONNECT response: %w", err)
	}
	respStr := string(br[:n])
	if !strings.Contains(respStr, "200") {
		// forward parent's response to client
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Parent proxy refused CONNECT\n"))
		upConn.Close()
		return fmt.Errorf("parent CONNECT failed: %s", strings.SplitN(respStr, "\r\n", 2)[0])
	}

	// Hijack client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		upConn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return fmt.Errorf("hijack not supported")
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		upConn.Close()
		http.Error(w, "Hijack failed", http.StatusInternalServerError)
		return fmt.Errorf("hijack: %w", err)
	}

	// write 200 OK to client to signify tunnel established
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		clientConn.Close()
		upConn.Close()
		return fmt.Errorf("write 200 to client: %w", err)
	}

	// Now copy bidirectionally
	go func() {
		defer clientConn.Close()
		defer upConn.Close()
		io.Copy(upConn, clientConn)
	}()
	go func() {
		defer clientConn.Close()
		defer upConn.Close()
		io.Copy(clientConn, upConn)
	}()

	return nil
}
