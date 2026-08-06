# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
