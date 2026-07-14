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
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
	Debug          bool     `json:"debug"`             // enable debug logging (e.g. client process ID)
	StopIfAuthFail bool     `json:"stop_if_auth_fail"` // stop when the parent proxy returns HTTP 407
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
		logFile = f
		defer logFile.Close()
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

	// transport that uses the parent proxy
	transport := &http.Transport{
		Proxy: http.ProxyURL(parentURL),
		DialContext: (&net.Dialer{
			Timeout:   connectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   false,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
	}

	var authenticationFailed atomic.Bool
	var stopOnce sync.Once
	var stopForAuthenticationFailure func()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if authenticationFailed.Load() {
			http.Error(w, "Proxy stopped: parent proxy authentication failed", http.StatusServiceUnavailable)
			return
		}
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
				if cfg.StopIfAuthFail && errors.Is(err, errParentProxyAuthentication) {
					stopForAuthenticationFailure()
				}
			}
			logger.Printf("TUNNELED %s%s %s %s in %s", clientIP, procInfo, r.Method, r.Host, time.Since(start))
			return
		}

		reqOut := r.Clone(r.Context())
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
		if cfg.StopIfAuthFail && resp.StatusCode == http.StatusProxyAuthRequired {
			stopForAuthenticationFailure()
		}

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
	stopForAuthenticationFailure = func() {
		stopOnce.Do(func() {
			authenticationFailed.Store(true)
			message := "ERROR parent proxy rejected credentials or requires authentication; stopping proxy"
			logger.Print(message)
			if logFile != nil {
				fmt.Fprintf(os.Stdout, "mini-proxy: %s\n", message)
			}
			transport.CloseIdleConnections()
			go func() {
				if err := httpServer.Close(); err != nil && err != http.ErrServerClosed {
					logger.Printf("FAILED stopping server after parent authentication error: %v", err)
				}
			}()
		})
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

func loadConfig(cfgPath string) (Config, error) {
	cfg := Config{StopIfAuthFail: true}
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
	for key, value := range raw {
		configForDecode[key] = value
	}
	configForDecode["password"], _ = json.Marshal(plainPassword)
	decodeData, _ := json.Marshal(configForDecode)
	if err := json.Unmarshal(decodeData, &cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
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
var errParentProxyAuthentication = errors.New("parent proxy authentication required or rejected")

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

	upConn, err := net.DialTimeout("tcp", parentAddr, connectTimeout)
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
	statusLine := strings.SplitN(respStr, "\r\n", 2)[0]
	if err := parentConnectStatusError(statusLine); errors.Is(err, errParentProxyAuthentication) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Parent proxy authentication failed\n"))
		upConn.Close()
		return err
	}
	if !strings.Contains(respStr, "200") {
		// forward parent's response to client
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Parent proxy refused CONNECT\n"))
		upConn.Close()
		return fmt.Errorf("parent CONNECT failed: %s", statusLine)
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

func parentConnectStatusError(statusLine string) error {
	if strings.HasPrefix(statusLine, "HTTP/") && strings.Contains(statusLine, " 407 ") {
		return fmt.Errorf("%w: %s", errParentProxyAuthentication, statusLine)
	}
	return nil
}
