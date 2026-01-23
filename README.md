# 3x-ui Node Deployment Script

Automated deployment script for 3x-ui VLESS proxy nodes. Deploys a complete production-ready node in minutes.

## Features

- ✅ **Fully automated** - one command deployment
- ✅ **36 system packages** - Docker, nginx, WireGuard, monitoring tools
- ✅ **Tailscale VPN** - ready to connect
- ✅ **2-hop VPN support** - WireGuard, iptables, conntrack for chaining
- ✅ **Prometheus metrics** - node-exporter for monitoring (port 9100)
- ✅ **Log aggregation** - Fluent Bit for Loki/Graylog (journald, Docker, files)
- ✅ **Network optimizations** - BBR, sysctl tuning, nginx worker tuning
- ✅ **3x-ui container** - latest from Docker Hub
- ✅ **Dual transports** - gRPC + XHTTP with Unix sockets
- ✅ **Anti-abuse firewall** - blocks SMTP, torrents, P2P
- ✅ **System verification** - health checks before reboot

## Quick Start

### One-liner (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/stein-hak/3x-ui-deploy/main/deploy-node.py | sudo python3 - --hostname node-vienna
```

### Clone and run

```bash
git clone https://github.com/stein-hak/3x-ui-deploy.git
cd 3x-ui-deploy
sudo ./deploy-node.py --hostname node-vienna
```

### Download and run

```bash
wget https://raw.githubusercontent.com/stein-hak/3x-ui-deploy/main/deploy-node.py
chmod +x deploy-node.py
sudo ./deploy-node.py --hostname vpn-node-01
```

## Usage

```bash
# With hostname, domain, and non-interactive mode (recommended for piped installation)
sudo ./deploy-node.py --hostname node-vienna --domain vpn.example.com --yes

# With hostname and domain (interactive)
sudo ./deploy-node.py --hostname node-vienna --domain vpn.example.com

# With hostname only (nginx step will prompt for domain)
sudo ./deploy-node.py --hostname node-vienna

# Without flags (interactive mode)
sudo ./deploy-node.py

# Show help
./deploy-node.py --help
```

**Flags:**
- `--hostname NAME` - Set system hostname (optional)
- `--domain NAME` - Domain name for nginx configuration (optional)
- `-y, --yes` - Non-interactive mode (auto-continue on errors, required for piped installation)

## What Gets Deployed

### Step 1: Install Required Packages (36 packages)
- **Adds Fluent Bit repository** automatically (official packages.fluentbit.io)
- Docker, docker-compose-v2
- nginx, certbot
- Monitoring: htop, iftop, nload, atop, speedtest-cli, prometheus-node-exporter, fluent-bit
- Network: socat, iperf3, wireguard, wireguard-tools, conntrack
- Utilities: vim, nano, screen, mc, jq
- Firewall: ufw, iptables, iptables-persistent
- **Disables monitoring services** (prometheus-node-exporter, fluent-bit) for configuration review
- Creates `/root/CONFIGURE_MONITORING_SERVICES.txt` with setup instructions

### Step 2: Install Tailscale
- Official Tailscale VPN client
- Ready to connect to your network

### Step 3: Optimize sysctl Values
- BBR congestion control
- TCP window scaling
- Increased buffer sizes
- File descriptor limits

### Step 4: Setup 3x-ui Docker Container
- Pulls `steinhak/3x-ui:latest` from Docker Hub
- Configurable admin credentials
- Data persistence in `/opt/3x-ui/data/`
- Health checking enabled

### Step 5: Configure gRPC + XHTTP Backends
- **gRPC Backend**: Unix socket (`/dev/shm/sync.sock`)
  - 30-40% performance improvement vs TCP
  - Service name: `api`
- **XHTTP Backend**: Unix socket (`/dev/shm/data.sock`)
  - Path: `/api`
  - Mode: packet-up (optimized for uploads)
  - External proxy: www.speedtest.net
  - Random padding for obfuscation
- No clients initially (add via panel)

### Step 6: Configure Nginx Reverse Proxy
- **Optimizes nginx.conf** for performance:
  - worker_connections: 4096 (up from 768)
  - multi_accept on, use epoll
  - tcp_nodelay on, tcp_nopush on
  - keepalive_timeout 65, keepalive_requests 100
  - Client timeout and buffer optimizations
  - Automatic backup before changes
- Creates **two** nginx configs in `/etc/nginx/sites-available/`:
  - `{domain}-http` - HTTP-only (for obtaining SSL certificate)
  - `{domain}-full` - Full HTTPS with gRPC + XHTTP backends
- Initially enables HTTP-only config
- Provides instructions to switch to full config after SSL
- Full config supports:
  - gRPC backend on `/sync` → `/dev/shm/sync.sock`
  - XHTTP backend on `/api` → `/dev/shm/data.sock`
  - SSL/TLS with Let's Encrypt
  - Security headers and compression
  - Static content and health endpoints

### Step 7: Configure Anti-Abuse Firewall
- Blocks SMTP (ports 25, 465, 587, 2525) - anti-spam
- Blocks BitTorrent (6881-6889, 51413) - anti-piracy
- Blocks DHT/tracker (6969, 1337)
- Blocks P2P (eDonkey, eMule)
- Rules persist across reboots

### Step 8: Configure Hostname
- Updates `/etc/hostname`
- Updates `/etc/hosts`
- Applies with `hostnamectl`

### Step 9: Final Check and Reboot
- Verifies Docker container health
- Checks iptables rules
- Confirms BBR enabled
- Optional reboot

## After Deployment

### 1. Connect Tailscale

```bash
tailscale up
```

### 2. Access Admin Panel

```bash
# Panel URL (localhost only)
http://localhost:2053/admin

# Check credentials
cat /opt/3x-ui/data/credentials.txt
```

### 3. Obtain SSL Certificate and Enable Full Config (if nginx was configured)

```bash
# Step 1: Obtain SSL certificate (nginx is running HTTP-only)
sudo certbot --nginx -d your-domain.com

# Step 2: Switch to full HTTPS config with gRPC + XHTTP backends
sudo rm /etc/nginx/sites-enabled/your_domain_com
sudo ln -s /etc/nginx/sites-available/your_domain_com-full /etc/nginx/sites-enabled/your_domain_com

# Step 3: Test and reload nginx
sudo nginx -t && sudo systemctl reload nginx
```

**What this does:**
- HTTP-only config allows certbot to obtain SSL certificate
- Full config adds HTTPS with both proxy backends (`/sync` and `/api`)
- Backends won't work until you switch to the full config

### 4. Add VLESS Clients

Use the web panel to add clients to the gRPC or XHTTP inbounds.

## Requirements

- **OS:** Ubuntu 20.04+ / Debian 11+
- **Privileges:** Root access (sudo)
- **Memory:** 512MB minimum, 1GB+ recommended
- **Disk:** 5GB+ free space
- **Network:** Public IPv4 address

## Troubleshooting

### Container not healthy

```bash
docker logs 3x-ui
docker ps -a
```

### Firewall rules not persisting

```bash
# Check rules
iptables -L DOCKER-USER -n -v

# Manually save
iptables-save > /etc/iptables/rules.v4
netfilter-persistent save
```

### BBR not enabled

```bash
# Check current
sysctl net.ipv4.tcp_congestion_control

# Reboot may be required
sudo reboot
```

## Docker Image

The script uses `steinhak/3x-ui:latest` from Docker Hub:
- https://hub.docker.com/r/steinhak/3x-ui
- Based on Alpine Linux
- Includes 3x-ui v2.8.5
- Health checking built-in

## Security Notes

- Admin panel binds to `127.0.0.1` only (not exposed)
- gRPC backend uses Unix socket (not exposed)
- Only ports 22, 80, 443 are open
- Anti-abuse firewall blocks malicious traffic
- Change default credentials immediately after deployment

## Support

- **Issues:** https://github.com/stein-hak/3x-ui-deploy/issues
- **Main repo:** https://github.com/stein-hak/3x-ui
- **Upstream:** https://github.com/MHSanaei/3x-ui

## License

MIT License - see main repository for details.
