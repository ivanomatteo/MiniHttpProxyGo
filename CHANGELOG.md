# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0]

### Added

- Add the `pac_url` and `pac_refresh_minutes` configuration options: a PAC script (URL or file) chooses, per request, `DIRECT` or the parent proxy to use, and is reloaded every `pac_refresh_minutes` (default `60`). `pac_url` and `parent_proxy` are mutually exclusive. When the PAC returns several entries, `CONNECT` tunnels and plain HTTP requests move to the next one if the connection to the current one fails.
- Add the `direct_hosts` configuration option: domains (and their subdomains) reached directly, with priority over `pac_url` and `parent_proxy`. `blocked_hosts` still takes precedence.
- Add tests for PAC parsing and evaluation, routing priority, failover between PAC entries, direct mode, loop detection and forwarding headers.

### Changed

- `parent_proxy` is now optional: when both `parent_proxy` and `pac_url` are empty, every request not blocked is sent directly to its destination. A request the proxy would send to itself is answered with `508 Loop Detected`.
- `stop_if_auth_fail` reacts only to a `407` returned by a proxy, not to one returned by a destination reached directly.
- Require Go 1.27 to build; the release workflow now takes the Go version from `go.mod`.
- Update the `golang.org/x/sys` and `golang.org/x/term` dependencies, and add `github.com/dop251/goja` to evaluate PAC scripts.

## [0.1.5] - 2026-09-28

### Added

- Add the `tcp_tunnel` configuration option: an array of direct TCP port forwards (e.g. `[{"source_addr":"127.0.0.1:2222","target_host":"10.0.0.10","target_port":22}]`). Each entry listens on `source_addr` and connects every accepted connection directly to the target, like `ssh -L`. Tunnels are independent of the HTTP proxy: they do not use the parent proxy, and `blocked_hosts` and `stop_if_auth_fail` do not apply to them. No tunnel is active when the option is omitted or empty.
- Add the `accept_tcp_connection_from` configuration option: source IP addresses and CIDR ranges allowed to connect to the TCP tunnels, separate from `accept_connection_from`. Defaults to loopback only (`127.0.0.1` and `::1`).
- Add the `accept_connection_from` configuration option: an array of source IP addresses and CIDR ranges (e.g. `["192.168.1.1", "192.168.20.0/24"]`) allowed to connect to the proxy. Connections from any other address are closed as soon as they are accepted and logged as `REJECTED`.
- Support plain `ws://` WebSockets and other HTTP `Upgrade` protocols sent to the proxy as regular requests. `wss://` continues to use `CONNECT` tunnels.

### Security

- Match `blocked_hosts` against the host name without its port. Previously any request carrying an explicit port, including every HTTPS `CONNECT` (`host:443`), bypassed the blocklist.
- Stop forwarding the client's own `Proxy-Authorization` header, and other hop-by-hop headers, to the parent proxy and the destination.
- Limit the time allowed for a client to send request headers.
- Accept client connections only from loopback addresses (`127.0.0.1` and `::1`) by default. Deployments listening on a non-loopback interface must list their clients in `accept_connection_from` to keep accepting them.

### Fixed

- Return redirects to the client instead of following them inside the proxy.
- Stream responses to the client as they arrive, so Server-Sent Events and other long-lived responses are no longer held back until they complete.
- Stop blocking domains that merely end with a blocked name: `example.com` no longer blocks `notexample.com`.
- Deliver the parent proxy's `407` response to the client before stopping on `stop_if_auth_fail`, instead of dropping the connection.
- Answer `502 Bad Gateway` when a `CONNECT` tunnel cannot be prepared, instead of an empty `200` that the client would treat as an established tunnel.
- Pass response bodies through unchanged instead of negotiating gzip compression with the destination on the client's behalf.
- Keep more idle connections to the parent proxy, which serves every plain HTTP request, reducing reconnections under load.
- Reject a `parent_proxy` with a scheme other than `http` or `https` at startup.

### Tests

- Add end-to-end tests through a parent proxy for redirects, header filtering, `ws://` upgrades and `stop_if_auth_fail`, and table tests for `blocked_hosts` matching.
- Cover `accept_connection_from` parsing, defaults, validation, and rejection of disallowed source addresses.

## [0.1.4] - 2026-08-06

### Fixed

- Preserve client data buffered immediately after an HTTP `CONNECT` request. This prevents TLS handshakes from stalling in clients that send the TLS ClientHello eagerly, including Outlook and Teams.
- Parse the parent proxy's complete `CONNECT` response instead of relying on a single fixed-size read.
- Validate the parent proxy response using its actual HTTP status code, including explicit handling of `407 Proxy Authentication Required` and all successful `2xx` responses.
- Preserve data buffered after the parent proxy's `CONNECT` response so that the first bytes from the destination are not lost.
- Apply a timeout while negotiating a tunnel with the parent proxy, preventing indefinitely stalled `CONNECT` requests.
- Use TCP half-close semantics when relaying tunnel traffic, improving the handling of long-lived connections, WebSockets, streaming traffic, and Teams calls.
- Establish a TLS connection when `parent_proxy` uses the `https://` scheme.
- Log a tunnel as `TUNNELED` only after it has completed successfully; failed relays are now reported as failures.

### Tests

- Add an end-to-end regression test covering a `CONNECT` request followed immediately by tunneled client data in the same write.
- Verify the tunnel implementation with the Go race detector and static analysis.

## [0.1.3] - 2026-07-14

### Changed

- Package Linux and Windows releases in separate archives, each containing only its own install and uninstall scripts.

## [0.1.2] - 2026-07-14

### Added

- Add the `stop_if_auth_fail` configuration option (default `true`): stop accepting connections when the parent proxy returns HTTP 407.
- Accept `[ask]` as `username` or `password` to request the value at console startup, with hidden password input. `[ask]` is rejected in service mode.
- Encrypt a plain `password` stored in the configuration at startup, using AES-GCM and the new `key_seed` option, which is generated when missing.
- Add the `-service` flag, used by the Systemd unit, to disable interactive prompts.

### Changed

- Include `uninstall.sh` in the release archives.

## [0.1.1] - 2026-07-10

### Added

- Add the `uninstall.sh` script for Linux, and include `uninstall.bat` in the release archives.

### Changed

- Bind the sample configuration to `127.0.0.1:3129` instead of all interfaces.

### Removed

- Remove the `timeout_sec` configuration option. Connections to the parent proxy use a fixed 30-second connect timeout, and requests are no longer cut off after 30 seconds as a whole.

## [0.1.0] - 2026-02-18

### Added

- First release: HTTP/HTTPS proxy forwarding to a parent proxy with Basic authentication, `blocked_hosts`, process identification in debug mode, and Systemd and Windows service support.

[Unreleased]: https://github.com/ivanomatteo/MiniHttpProxyGo/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/ivanomatteo/MiniHttpProxyGo/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/ivanomatteo/MiniHttpProxyGo/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/ivanomatteo/MiniHttpProxyGo/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/ivanomatteo/MiniHttpProxyGo/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ivanomatteo/MiniHttpProxyGo/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ivanomatteo/MiniHttpProxyGo/releases/tag/v0.1.0
