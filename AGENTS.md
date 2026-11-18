# AGENTS.md

Lightweight HTTP/HTTPS forward proxy in Go (module `mini-proxy`, package `main`), with parent proxy auth, PAC, direct/blocked hosts, TCP tunnels, optional in-memory HTTP cache, and Windows/Linux service support.

## Layout
- `mini-proxy.go` — config loading/encryption, routing, `ServeHTTP`, CONNECT tunnels, TCP tunnels.
- `pac.go` — PAC loading/refresh and evaluation (goja JS runtime).
- `httpcache/` — standalone RFC 9111 shared cache (`policy.go`, `store.go`, `roundtrip.go`).
- Platform-specific files use build tags: `*_linux.go`, `*_windows.go`, `*_other.go`, `*_default.go`. Keep every platform compiling when changing one.

## Commands
- Build: `./build.sh` (Linux) or `./build.sh --windows`
- Test: `go test ./...`
- Check Windows build: `GOOS=windows go build ./...` (also `go vet ./...`)
- Releases: GoReleaser on `v*` tags (`.github/workflows/release.yml`).

## Conventions
- Standard library first; add dependencies only when really needed.
- Format with `gofmt`. Add or update tests (`*_test.go`) for every behavior change.
- New config options: add them to `Config`, `sample-config.json`, the config table in `ReadMe.md`, and `CHANGELOG.md` (Keep a Changelog format).
- Never log credentials. Plain passwords in the config are rewritten encrypted at startup; `[ask]` is console-only.
- Routing order is fixed: `blocked_hosts` → `direct_hosts` → PAC or `parent_proxy` (mutually exclusive) → direct.
- Don't commit `config*.json`, `*.log`, or built binaries.
