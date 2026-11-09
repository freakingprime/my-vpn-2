# my-vpn-2 — Ultra-Lightweight Multi-Target HTTPS Proxy Gateway

An ultra-lightweight Go HTTP/HTTPS Proxy Gateway and Web Controller that lets your devices (browsers, phones, apps on LAN or Tailscale) dynamically route traffic through three selectable exit points:

1. **Direct (Local ISP)**: Routes directly out through your local internet connection. Both GCE SSH and Gluetun sleep (`0` background load).
2. **Google Cloud / VPS VM (SSH Tunnel)**: Connects an on-demand encrypted SSH tunnel via `golang.org/x/crypto/ssh` to your configured remote server (`GCE_HOST`).
3. **VPNGate Public VPN (`vpngate.net`)**: Starts `qmcgaw/gluetun` (`my-vpn-2-vpn`) on-demand with your selected volunteer OpenVPN server.

## Endpoints

- **Web UI Dashboard**: `http://<YOUR_SERVER_IP>:<WEB_PORT>` (default `:8080`)
- **HTTP / HTTPS (`CONNECT`) Proxy**: `<YOUR_SERVER_IP>:<PROXY_PORT>` (default `:8888`, restricted to private LAN & Tailscale subnets)
- **PAC (Proxy Auto-Config) URL**: `http://<YOUR_SERVER_IP>:<WEB_PORT>/proxy.pac`

## Key Features

- **Battle-Tested Go Stack**: Built with [`elazarl/goproxy`](https://github.com/elazarl/goproxy) and [`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh) in a single ~12 MB static binary.
- **Pre-Built Public Container Image**: Automatically built via GitHub Actions and published to `ghcr.io/freakingprime/my-vpn-2:latest` (`linux/amd64`).
- **4-Hour Inactivity Auto-Shutoff**: Automatically switches back to **Direct (Local ISP)** and stops Gluetun / closes SSH after 4 hours of proxy inactivity.
- **Fail-Closed Switching**: Blocks proxy requests while a target tunnel is starting/handshaking so your home IP never leaks during transitions.
- **On-Demand Ping & Country Grouping**: Probes both TCP and UDP OpenVPN servers and sorts reachable servers by score and latency.

## Quick Start (Docker Compose)

1. Copy `.env.example` to `.env` and configure your ports and optional SSH tunnel settings:
   ```bash
   cp .env.example .env
   ```
2. Start the stack:
   ```bash
   docker compose up -d
   ```

For **Synology DSM 7.2+ Container Manager** deployment instructions, see [`synology/README.md`](synology/README.md).
