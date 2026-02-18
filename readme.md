# Mini Proxy

A lightweight HTTP/HTTPS proxy written in Go. It supports parent proxy forwarding with authentication, host blacklisting, and can run as a system service on both Windows and Linux.

## Features
- **Parent Proxy Forwarding**: Forward requests to another HTTP/HTTPS proxy.
- **Authentication**: Supports Basic Auth for the parent proxy.
- **Host Blacklisting**: Block specific domains or suffixes (e.g., `facebook.com`, `ads.example.com`).
- **Process Identification (Debug Mode)**: On Linux and Windows, identifies which local process is making the request.
- **Service Integration**: Fully compatible with Systemd (Linux) and Service Control Manager (Windows).
- **Graceful Shutdown**: Handles signals for clean termination.

## Configuration
Create a `config.json` file (see `sample-config.json`):

```json
{
  "listen_addr": ":3128",
  "parent_proxy": "http://proxy.example.com:8080",
  "username": "your_user",
  "password": "your_password",
  "log_file": "proxy.log",
  "blocked_hosts": ["facebook.com", "ads.example.com"],
  "timeout_sec": 30,
  "debug": true
}
```

### Configuration Fields
| Field | Description |
|-------|-------------|
| `listen_addr` | Address and port to listen on (e.g., `:3128`). |
| `parent_proxy` | URL of the upstream proxy. |
| `username` | (Optional) Username for parent proxy authentication. |
| `password` | (Optional) Password for parent proxy authentication. |
| `log_file` | Path to the log file. If empty, logs to stdout. |
| `blocked_hosts` | Array of hosts to block. Suffix matching is supported. |
| `timeout_sec` | Timeout for network operations in seconds (default: 30). |
| `debug` | Enable extended logging, including process identification for local requests. |

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
