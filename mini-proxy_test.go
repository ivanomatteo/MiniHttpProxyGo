package main

import (
	"bytes"
	"strings"
	"testing"
)

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
