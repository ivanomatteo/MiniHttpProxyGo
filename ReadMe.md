# Mini Http Proxy Go

A lightweight HTTP/HTTPS proxy written in Go. It supports parent proxy forwarding with authentication, PAC scripts, direct connections, host blacklisting, and can run as a system service on both Windows and Linux.

## Features
- **Parent Proxy Forwarding**: Forward requests to another HTTP/HTTPS proxy, or connect directly when none is configured.
- **PAC Support**: Choose the upstream per request with a proxy auto-config script.
- **Direct Hosts**: Reach selected domains directly, bypassing the parent proxy and the PAC.
- **Tunnels and WebSockets**: HTTPS and `wss://` through `CONNECT` tunnels; plain `ws://` (and other HTTP `Upgrade` protocols) forwarded as upgraded connections.
- **Transparent Forwarding**: Redirects, streaming responses (e.g. Server-Sent Events) and compressed bodies are passed to the client unchanged.
- **Authentication**: Supports Basic Auth for the parent proxy.
- **Source IP Filtering**: Accept client connections only from allowed IP addresses or CIDR ranges (loopback only by default).
- **Host Blacklisting**: Block specific domains or suffixes (e.g., `facebook.com`, `ads.example.com`).
- **Process Identification (Debug Mode)**: On Linux and Windows, identifies which local process is making the request.
- **Service Integration**: Fully compatible with Systemd (Linux) and Service Control Manager (Windows).
- **Graceful Shutdown**: Handles signals for clean termination.

## Releases
🚀 Download latest release from **[GitHub Releases](https://github.com/ivanomatteo/MiniHttpProxyGo/releases/latest)**.

## Configuration
Create a `config.json` file (see `sample-config.json`):

```json
{
  "listen_addr": "127.0.0.1:3128",
  "accept_connection_from": ["127.0.0.1", "::1"],
  "parent_proxy": "http://proxy.example.com:8080",
  "username": "your_user",
  "password": "your_password",
  "log_file": "proxy.log",
  "blocked_hosts": ["facebook.com", "ads.example.com"],
  "direct_hosts": ["intranet.example.com", "localhost"],
  "debug": true,
  "stop_if_auth_fail": true,
  "tcp_tunnel": [
    {"source_addr": "127.0.0.1:2222", "target_host": "10.0.0.10", "target_port": 22}
  ],
  "accept_tcp_connection_from": ["127.0.0.1", "::1"]
}
```

### Configuration Fields
| Field | Description |
|-------|-------------|
| `listen_addr` | Address and port to listen on (e.g., `:3128`). |
| `accept_connection_from` | Array of source IP addresses and CIDR ranges allowed to connect (e.g., `["192.168.1.1", "192.168.20.0/24"]`). Defaults to `["127.0.0.1", "::1"]` when omitted. |
| `parent_proxy` | URL of the upstream proxy (`http://` or `https://`). Optional and mutually exclusive with `pac_url`: when both are empty, every request not blocked is sent directly to its destination (see [Routing](#routing)). |
| `username` | Username for parent proxy authentication. Leave empty to omit it, set to `[ask]` to request it at console startup, or provide a fixed value. |
| `password` | Password for parent proxy authentication. Leave empty to omit it, set to `[ask]` to request it at console startup, or provide a fixed value. |
| `key_seed` | 20-character seed used to encrypt the stored password. It is generated automatically when missing. |
| `log_file` | Path to the log file. If empty, logs to stdout. |
| `blocked_hosts` | Array of domains to block. An entry blocks the domain itself and all of its subdomains, on any port (e.g. `example.com` blocks `example.com:443` and `www.example.com`, but not `notexample.com`). |
| `direct_hosts` | Array of domains reached directly, without the parent proxy and without consulting the PAC. Entries match like `blocked_hosts` (domain and subdomains, any port); `blocked_hosts` takes precedence. |
| `debug` | Enable extended logging, including process identification for local requests. |
| `stop_if_auth_fail` | Stop accepting connections when the parent proxy returns HTTP 407. The request that received the 407 still gets its response; requests already in progress get up to 5 seconds to complete. Defaults to `true`; set to `false` to keep forwarding requests. |
| `pac_url` | `http(s)://` URL or local path of a PAC script that chooses the upstream for every request (see [PAC Support](#pac-support)). A relative path is resolved against the executable directory, like `log_file`. Mutually exclusive with `parent_proxy`: setting both prevents startup. |
| `pac_refresh_minutes` | Minutes between PAC reloads. Defaults to `60`; `0` disables reloading. A failed reload keeps the previous script. |
| `tcp_tunnel` | Array of direct TCP port forwards, independent of the proxy (see [TCP Tunnels](#tcp-tunnels)). Omit it or leave it empty to disable tunnels. |
| `accept_tcp_connection_from` | Array of source IP addresses and CIDR ranges allowed to connect to the TCP tunnels, with the same syntax as `accept_connection_from`. Defaults to `["127.0.0.1", "::1"]` when omitted. |

Authentication is disabled when both `username` and `password` are empty. In console mode, each field set to `[ask]` is requested interactively at startup; password input is hidden and credentials are never written to the log. The `[ask]` value is not supported in service mode: startup fails with an error, because a service has no interactive console. Configure fixed credentials (or leave both fields empty) before installing or starting the service.

When `password` is a non-empty plain string, the proxy encrypts it at startup and atomically rewrites the configuration as `{"encrypted":"..."}`. Existing encrypted values are decrypted only in memory. Encryption uses AES-GCM and a key derived from `SHA1(SHA1(key_seed) + username)`; changing either `key_seed` or `username` makes an existing encrypted password unreadable. Empty passwords and `[ask]` remain strings because they are control values rather than stored secrets.

### Routing
Each request is routed by the first rule that matches:

1. `blocked_hosts`: answered with `403 Forbidden`.
2. `direct_hosts`: connected directly to the destination.
3. `pac_url` or `parent_proxy` (only one can be set): the PAC script chooses `DIRECT` or the proxies to use, or the request is forwarded to the parent proxy.
4. Otherwise (no `pac_url` and no `parent_proxy`): connected directly to the destination.

`stop_if_auth_fail` reacts only to a `407` received from a proxy the request was sent through, because only then were the credentials used. On a `DIRECT` route the `407` is simply passed to the client.

A request that the proxy would send to itself (e.g. a `DIRECT` request for the proxy's own address) is answered with `508 Loop Detected` instead of being forwarded again.

### PAC Support

Set `pac_url` to let a [PAC script](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file) decide, per request, whether to go `DIRECT` or through which parent proxy. The script runs in an embedded JavaScript interpreter with no filesystem or network access, except the DNS lookups made by `dnsResolve()`, `isResolvable()` and `isInNet()` (2 seconds each); each evaluation is limited to 5 seconds.

- `PROXY`, `HTTP` and `HTTPS` entries are supported; `SOCKS*` entries are skipped. `username`/`password` are sent to every proxy the PAC returns.
- Multiple entries (`PROXY a:8080; PROXY b:8080; DIRECT`) are tried in order, for both `CONNECT` tunnels and plain HTTP requests. The next entry is used only when the connection to the current one cannot be established, so the request was not sent yet; a response (including `407`) or an error after sending ends the attempt.
- The PAC is downloaded directly (never through a proxy) and limited to 1 MiB.
- If the PAC fails to evaluate, the request is answered with `502`; it never falls back to `DIRECT`. A PAC that fails to load at startup prevents startup; a failed periodic reload keeps the previous script.
- `direct_hosts` are matched before the PAC is evaluated.
- Not implemented: `weekdayRange()`, `dateRange()`, `timeRange()`.

### Source IP Filtering
Every incoming connection is checked against `accept_connection_from` as soon as it is accepted, before any request data is read. Connections from other addresses are closed immediately and logged as `REJECTED`.

- Each entry is either a single IP address (IPv4 or IPv6) or a CIDR range such as `192.168.20.0/24` or `fd00::/8`.
- When the field is omitted, only loopback clients (`127.0.0.1` and `::1`) are accepted. Remember to add the addresses of other hosts when `listen_addr` is not bound to loopback only (e.g. `:3128`).
- IPv4 clients reaching a dual-stack listener as IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are matched against the IPv4 entries.
- An empty array or an invalid entry is a configuration error and prevents startup. To accept any source explicitly, use `["0.0.0.0/0", "::/0"]`.

### TCP Tunnels
Each `tcp_tunnel` entry is a plain port forward, like `ssh -L` or a netcat relay: the program listens on `source_addr` and connects every accepted connection directly to `target_host:target_port`. Tunnels are independent of the HTTP proxy: they never use the parent proxy or its credentials.

| Field | Description |
|-------|-------------|
| `source_addr` | Local address and port to listen on. Like `listen_addr`, the host part selects the interface to bind (`127.0.0.1:2222` for loopback only, `:2222` for all interfaces). |
| `target_host` | Destination host name or IP address, resolved locally. |
| `target_port` | Destination port (1-65535). |

With the example configuration above, `ssh -p 2222 user@127.0.0.1` reaches the SSH server on `10.0.0.10:22`.

- Connections are filtered by `accept_tcp_connection_from`, checked the same way as `accept_connection_from` for the proxy. The two lists are independent.
- `blocked_hosts` and `stop_if_auth_fail` apply only to the HTTP proxy. When the proxy stops after a parent `407`, the tunnels keep running until the program is stopped.
- An invalid entry, or a `source_addr` that cannot be bound, prevents startup.

## Debug Mode: Process Identification
When `debug` is set to `true`, the proxy attempts to identify the local process initiating the request.
- **Linux**: Parses `/proc/net/tcp` and `/proc/[pid]/fd` to match the connection to a PID and command line.
- **Windows**: Uses `netstat` and `tasklist` to identify the source PID and executable name.

This is particularly useful for auditing which applications are generating traffic.

## Installation

### Linux (Systemd)
1. Build the binary: `go build -o mini-proxy .`
2. Run the installation script:
   ```bash
   chmod +x install.sh
   sudo ./install.sh
   ```
   The script creates a dedicated `mini-proxy` user, installs the binary to `/opt/mini-proxy`, and sets up the Systemd service.
3. Manage the service:
   ```bash
   sudo systemctl status mini-proxy
   sudo systemctl restart mini-proxy
   ```

### Windows
1. Build the binary for Windows:
   ```bash
   GOOS=windows GOARCH=amd64 go build -o mini-proxy.exe .
   ```
2. Run `install.bat` as Administrator.
   This will install the service using the Service Control Manager (SCM).
3. The service `mini-proxy` will be created and started. Configuration and executable are located in `C:\mini-proxy`.

## Uninstallation

### Linux (Systemd)

Run the uninstallation script as root:

```bash
sudo ./uninstall.sh
```

This stops and disables the `mini-proxy` service, removes its Systemd unit, and preserves `/opt/mini-proxy`, the configuration, and the dedicated user. To remove the installation directory, user, and group as well, use:

```bash
sudo ./uninstall.sh --purge
```

### Windows

Run `uninstall.bat` as Administrator. The script stops and deletes the `mini-proxy` service, but preserves the installation directory `C:\mini-proxy`. Delete that directory manually if the configuration and installed files are no longer needed.

## Build
To build for the current platform:
```bash
go build -o mini-proxy .
```

Alternatively, use the provided `build.sh` script:
```bash
./build.sh           # Build for current platform
./build.sh --windows # Build for Windows (cross-compile)
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
