# 3x-ui Node Deployment Script

Automated deployment script for 3x-ui VLESS proxy nodes. Deploys a complete production-ready node in minutes.

## Features

- ✅ **Fully automated** - one command deployment
- ✅ **29 system packages** - Docker, nginx, Python requests, monitoring tools
- ✅ **Tailscale VPN** - ready to connect
- ✅ **Network optimizations** - BBR, sysctl tuning
- ✅ **3x-ui container** - latest from Docker Hub
- ✅ **Unix socket gRPC** - 30-40% performance boost
- ✅ **Anti-abuse firewall** - blocks SMTP, torrents, P2P
- ✅ **System verification** - health checks before reboot

## Quick Start

### One-liner (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/steinhak/3x-ui-deploy/main/deploy-node.py | sudo python3 - --hostname node-vienna
```

### Clone and run

```bash
git clone https://github.com/steinhak/3x-ui-deploy.git
cd 3x-ui-deploy
sudo ./deploy-node.py --hostname node-vienna
```

### Download and run

```bash
wget https://raw.githubusercontent.com/steinhak/3x-ui-deploy/main/deploy-node.py
chmod +x deploy-node.py
sudo ./deploy-node.py --hostname vpn-node-01
```

## Usage

```bash
# With hostname and non-interactive mode (recommended for piped installation)
sudo ./deploy-node.py --hostname node-vienna --yes

# With hostname (interactive)
sudo ./deploy-node.py --hostname node-vienna

# Without hostname (hostname step will be skipped)
sudo ./deploy-node.py

# Show help
./deploy-node.py --help
```

**Flags:**
- `--hostname NAME` - Set system hostname
- `-y, --yes` - Non-interactive mode (auto-continue on errors, required for piped installation)

## What Gets Deployed

### Step 1: Install Required Packages (29 packages)
- Docker, docker-compose-v2
- nginx, certbot
- Monitoring: htop, iftop, nload, atop
- Network: socat, iperf3
- Utilities: vim, nano, screen, mc, jq
- Firewall: ufw, iptables-persistent

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

### Step 5: Configure gRPC Backend
- Unix socket transport (`/dev/shm/xui-grpc.sock`)
- 30-40% performance improvement vs TCP
- gRPC service name: `api`
- No clients initially (add via panel)

### Step 6: Configure Anti-Abuse Firewall
- Blocks SMTP (ports 25, 465, 587, 2525) - anti-spam
- Blocks BitTorrent (6881-6889, 51413) - anti-piracy
- Blocks DHT/tracker (6969, 1337)
- Blocks P2P (eDonkey, eMule)
- Rules persist across reboots

### Step 7: Configure Hostname
- Updates `/etc/hostname`
- Updates `/etc/hosts`
- Applies with `hostnamectl`

### Step 8: Final Check and Reboot
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

### 3. Setup Nginx Reverse Proxy

See main documentation for nginx configuration with SSL.

### 4. Add VLESS Clients

Use the web panel or `xui-client` script to add clients.

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

- **Issues:** https://github.com/steinhak/3x-ui-deploy/issues
- **Main repo:** https://github.com/steinhak/3x-ui
- **Upstream:** https://github.com/MHSanaei/3x-ui

## License

MIT License - see main repository for details.
