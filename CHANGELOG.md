# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
- Preserve client data buffered immediately after an HTTP `CONNECT` request. This prevents TLS handshakes from stalling in clients that send the TLS ClientHello eagerly, including Outlook and Teams.
- Parse the parent proxy's complete `CONNECT` response instead of relying on a single fixed-size read.
- Validate the parent proxy response using its actual HTTP status code, including explicit handling of `407 Proxy Authentication Required` and all successful `2xx` responses.
- Preserve data buffered after the parent proxy's `CONNECT` response so that the first bytes from the destination are not lost.
- Apply a timeout while negotiating a tunnel with the parent proxy, preventing indefinitely stalled `CONNECT` requests.
- Use TCP half-close semantics when relaying tunnel traffic, improving the handling of long-lived connections, WebSockets, streaming traffic, and Teams calls.
- Establish a TLS connection when `parent_proxy` uses the `https://` scheme.
- Log a tunnel as `TUNNELED` only after it has completed successfully; failed relays are now reported as failures.

### Tests

- Add end-to-end tests through a parent proxy for redirects, header filtering, `ws://` upgrades and `stop_if_auth_fail`, and table tests for `blocked_hosts` matching.
- Cover `accept_connection_from` parsing, defaults, validation, and rejection of disallowed source addresses.
- Add an end-to-end regression test covering a `CONNECT` request followed immediately by tunneled client data in the same write.
- Verify the tunnel implementation with the Go race detector and static analysis.
