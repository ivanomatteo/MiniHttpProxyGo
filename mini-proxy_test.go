package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

	parentURL, err := url.Parse("http://" + parentListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := handleConnect(w, r, parentURL, "", log.New(io.Discard, "", 0)); err != nil {
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
