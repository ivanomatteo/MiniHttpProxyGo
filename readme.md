# Mini Proxy

A simple HTTP/HTTPS proxy in Go that supports parent proxy forwarding with authentication, host blacklisting, and runs as a service on both Windows and Linux.

## Features
- Forwarding to a parent proxy (HTTP/HTTPS)
- Basic Auth support for parent proxy
- Host blacklisting (exact or suffix match)
- Graceful shutdown
- Runs as a Windows Service (SCM compatible)
- Runs as a Linux Service (Systemd compatible)
- Can be run as a standalone executable

## Build
To build for the current platform:
```bash
go build -o mini-proxy .
```

To build for Windows (from Linux):
```bash
GOOS=windows GOARCH=amd64 go build -o mini-proxy.exe .
```

Alternatively, use the provided `build.sh` script.

## Installation

### Windows
1. Run `install.bat` as Administrator.
2. The service `mini-proxy` will be created and started.
3. Configuration and executable are located in `C:\mini-proxy`.

### Linux
1. Run `install.sh`.
2. The service is managed via `systemctl`.

## Configuration
Edit `config.json`:
```json
{
  "listen_addr": ":3128",
  "parent_proxy": "http://proxy.example.com:8080",
  "username": "your_user",
  "password": "your_password",
  "log_file": "proxy.log",
  "blocked_hosts": ["facebook.com", "ads.example.com"],
  "timeout_sec": 30
}
```

## Running as standalone
```bash
./mini-proxy -config config.json
```
