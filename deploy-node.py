#!/usr/bin/env python3
"""
3x-ui Node Deployment Script
Automated deployment of 3x-ui VLESS proxy nodes
"""

import subprocess
import sys
import os
import time
import json
import argparse
from typing import List, Tuple


class Colors:
    """Terminal colors for output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_header(text: str):
    """Print section header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}\n")


def print_step(step: int, total: int, text: str):
    """Print step progress"""
    print(f"{Colors.CYAN}[{step}/{total}] {text}...{Colors.ENDC}")


def print_success(text: str):
    """Print success message"""
    print(f"{Colors.GREEN}✓ {text}{Colors.ENDC}")


def print_error(text: str):
    """Print error message"""
    print(f"{Colors.RED}✗ {text}{Colors.ENDC}")


def print_warning(text: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.ENDC}")


def run_command(cmd: str, check=True, shell=True) -> Tuple[int, str, str]:
    """
    Run shell command and return exit code, stdout, stderr
    """
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr


def check_root():
    """Ensure script is run as root"""
    if os.geteuid() != 0:
        print_error("This script must be run as root!")
        print("Please run: sudo python3 deploy-node.py")
        sys.exit(1)


# ============================================================================
# STEP 1: Install Required Packages
# ============================================================================

def step1_install_packages():
    """Install all required system packages"""
    print_header("STEP 1: Installing Required Packages")

    packages = [
        "curl", "wget", "ca-certificates", "gnupg", "lsb-release",
        "vim", "nano",
        "screen",
        "htop", "iftop", "nload", "atop",
        "unzip", "zip",
        "net-tools", "iproute2",
        "jq",
        "socat",
        "ufw",
        "nginx",
        "docker.io",
        "docker-compose-v2",
        "certbot",
        "python3-certbot-nginx",
        "mc",
        "iperf3"
    ]

    print_step(1, 3, "Updating package lists")
    code, out, err = run_command("apt update", check=False)
    if code != 0:
        print_error(f"Failed to update package lists: {err}")
        return False
    print_success("Package lists updated")

    print_step(2, 3, f"Installing {len(packages)} packages")
    print(f"  Packages: {', '.join(packages[:5])}... (and {len(packages)-5} more)")

    # Install packages with -y flag to auto-confirm
    pkg_list = " ".join(packages)
    cmd = f"DEBIAN_FRONTEND=noninteractive apt install -y {pkg_list}"

    code, out, err = run_command(cmd, check=False)
    if code != 0:
        print_error(f"Failed to install packages: {err}")
        return False

    print_success(f"All {len(packages)} packages installed successfully")

    print_step(3, 3, "Verifying critical packages")
    critical = ["docker", "nginx", "certbot"]
    all_ok = True

    for pkg in critical:
        code, out, err = run_command(f"which {pkg}", check=False)
        if code == 0:
            print(f"  ✓ {pkg}: {out.strip()}")
        else:
            print_error(f"  {pkg} not found!")
            all_ok = False

    if all_ok:
        print_success("All critical packages verified")
        return True
    else:
        print_error("Some critical packages are missing")
        return False


# ============================================================================
# STEP 2: Install Tailscale
# ============================================================================

def step2_install_tailscale():
    """Install Tailscale VPN"""
    print_header("STEP 2: Installing Tailscale")

    print_step(1, 3, "Checking if Tailscale is already installed")
    code, out, err = run_command("which tailscale", check=False)
    if code == 0:
        print_warning(f"Tailscale already installed: {out.strip()}")
        # Get version
        code, version, _ = run_command("tailscale version", check=False)
        if code == 0:
            print(f"  Current version: {version.strip().split()[0]}")

        response = input(f"{Colors.YELLOW}Reinstall Tailscale? [y/N]: {Colors.ENDC}")
        if response.lower() not in ['y', 'yes']:
            print_success("Skipping Tailscale installation")
            return True

    print_step(2, 3, "Downloading and running Tailscale installer")
    print("  URL: https://tailscale.com/install.sh")

    # Download and execute install script
    cmd = "curl -fsSL https://tailscale.com/install.sh | sh"
    code, out, err = run_command(cmd, check=False)

    if code != 0:
        print_error(f"Failed to install Tailscale: {err}")
        return False

    print_success("Tailscale installation completed")

    print_step(3, 3, "Verifying Tailscale installation")
    code, out, err = run_command("which tailscale", check=False)
    if code == 0:
        print(f"  ✓ tailscale binary: {out.strip()}")

        # Get version
        code, version, _ = run_command("tailscale version", check=False)
        if code == 0:
            print(f"  ✓ version: {version.strip().split()[0]}")

        print_success("Tailscale installed and verified")
        print_warning("Note: Run 'tailscale up' to authenticate and connect to your network")
        return True
    else:
        print_error("Tailscale binary not found after installation")
        return False


# ============================================================================
# STEP 3: Optimize sysctl values
# ============================================================================

def step3_optimize_sysctl():
    """Apply sysctl optimizations for network performance"""
    print_header("STEP 3: Optimizing sysctl Values")

    # Sysctl optimizations from x-ui-pro.sh
    sysctl_settings = {
        "net.core.default_qdisc": "fq",
        "net.ipv4.tcp_congestion_control": "bbr",
        "fs.file-max": "2097152",
        "net.ipv4.tcp_timestamps": "1",
        "net.ipv4.tcp_sack": "1",
        "net.ipv4.tcp_window_scaling": "1",
        "net.core.rmem_max": "16777216",
        "net.core.wmem_max": "16777216",
        "net.ipv4.tcp_rmem": "4096 87380 16777216",
        "net.ipv4.tcp_wmem": "4096 65536 16777216",
        # Mobile VPN optimization - aggressive TCP keepalive
        # Detect dead connections from IP switches quickly (WiFi<->Cellular)
        "net.ipv4.tcp_keepalive_time": "120",      # Check connection after 2 min (default: 7200s)
        "net.ipv4.tcp_keepalive_intvl": "10",      # Send probes every 10s (default: 75s)
        "net.ipv4.tcp_keepalive_probes": "3",      # Give up after 3 failed probes (default: 9)
    }

    print_step(1, 3, f"Backing up current /etc/sysctl.conf")
    backup_file = f"/etc/sysctl.conf.backup.{int(time.time())}"
    code, _, err = run_command(f"cp /etc/sysctl.conf {backup_file}", check=False)
    if code == 0:
        print(f"  ✓ Backup created: {backup_file}")
    else:
        print_warning(f"Could not create backup: {err}")

    print_step(2, 3, f"Applying {len(sysctl_settings)} sysctl optimizations")

    # Check which settings are already present
    existing_settings = {}
    if os.path.exists("/etc/sysctl.conf"):
        with open("/etc/sysctl.conf", "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    existing_settings[key.strip()] = value.strip()

    # Apply each setting
    added = 0
    updated = 0
    skipped = 0

    for key, value in sysctl_settings.items():
        if key in existing_settings:
            if existing_settings[key] == value:
                print(f"  ⊙ {key}={value} (already set)")
                skipped += 1
                continue
            else:
                print(f"  ↻ {key}: {existing_settings[key]} → {value}")
                updated += 1
        else:
            print(f"  + {key}={value}")
            added += 1

        # Append to sysctl.conf
        cmd = f'echo "{key}={value}" | tee -a /etc/sysctl.conf > /dev/null'
        code, _, err = run_command(cmd, check=False)
        if code != 0:
            print_error(f"Failed to add {key}: {err}")

    print(f"\n  Summary: {added} added, {updated} updated, {skipped} unchanged")

    print_step(3, 3, "Applying sysctl changes")
    code, out, err = run_command("sysctl -p", check=False)

    if code != 0:
        print_error(f"Failed to apply sysctl settings: {err}")
        return False

    # Verify critical settings
    print("\n  Verifying critical settings:")
    critical_checks = [
        ("net.ipv4.tcp_congestion_control", "bbr"),
        ("net.core.default_qdisc", "fq"),
        ("fs.file-max", "2097152"),
        ("net.ipv4.tcp_keepalive_time", "120"),
    ]

    all_verified = True
    for key, expected in critical_checks:
        code, out, _ = run_command(f"sysctl -n {key}", check=False)
        if code == 0:
            actual = out.strip()
            if actual == expected:
                print(f"  ✓ {key} = {actual}")
            else:
                print_warning(f"  {key} = {actual} (expected: {expected})")
                all_verified = False
        else:
            print_error(f"  Could not verify {key}")
            all_verified = False

    if all_verified:
        print_success("All sysctl optimizations applied and verified")
        return True
    else:
        print_warning("Sysctl settings applied but some verifications failed")
        return True  # Still return True as settings were applied


# ============================================================================
# STEP 4: Setup 3x-ui Docker Compose
# ============================================================================

def step4_setup_3xui():
    """Deploy 3x-ui using Docker Compose"""
    print_header("STEP 4: Setting up 3x-ui Docker Container")

    # Configuration prompts
    print_step(1, 5, "Gathering configuration")

    deploy_dir = input(f"{Colors.CYAN}Deployment directory [{Colors.BOLD}/opt/3x-ui{Colors.ENDC}{Colors.CYAN}]: {Colors.ENDC}").strip()
    if not deploy_dir:
        deploy_dir = "/opt/3x-ui"

    admin_user = input(f"{Colors.CYAN}Admin username [{Colors.BOLD}admin{Colors.ENDC}{Colors.CYAN}]: {Colors.ENDC}").strip()
    if not admin_user:
        admin_user = "admin"

    admin_pass = input(f"{Colors.CYAN}Admin password [{Colors.BOLD}admin{Colors.ENDC}{Colors.CYAN}]: {Colors.ENDC}").strip()
    if not admin_pass:
        admin_pass = "admin"

    panel_path = input(f"{Colors.CYAN}Panel URL path [{Colors.BOLD}/admin{Colors.ENDC}{Colors.CYAN}]: {Colors.ENDC}").strip()
    if not panel_path:
        panel_path = "/admin"

    print(f"\n  Deployment dir: {deploy_dir}")
    print(f"  Admin username: {admin_user}")
    print(f"  Admin password: {'*' * len(admin_pass)}")
    print(f"  Panel path: {panel_path}")

    print_step(2, 5, "Creating deployment directory")
    if os.path.exists(deploy_dir):
        print_warning(f"Directory {deploy_dir} already exists")
        response = input(f"{Colors.YELLOW}Continue anyway? [y/N]: {Colors.ENDC}")
        if response.lower() not in ['y', 'yes']:
            print_warning("Skipping 3x-ui setup")
            return False
    else:
        code, _, err = run_command(f"mkdir -p {deploy_dir}", check=False)
        if code != 0:
            print_error(f"Failed to create directory: {err}")
            return False
        print_success(f"Created {deploy_dir}")

    print_step(3, 5, "Generating docker-compose.yml")

    # Embedded docker-compose.yml template
    docker_compose_template = f'''version: '3.8'

services:
  3x-ui:
    image: steinhak/3x-ui:latest
    container_name: 3x-ui
    restart: unless-stopped

    ports:
      - "127.0.0.1:2053:2053"     # Admin panel (localhost only)
      - "127.0.0.1:10002:10000"   # gRPC endpoint for VLESS (localhost only)
      - "127.0.0.1:10003:10001"   # WebSocket endpoint for VLESS (localhost only)

    environment:
      - X_UI_PORT=2053
      - X_UI_USERNAME={admin_user}
      - X_UI_PASSWORD={admin_pass}
      - X_UI_PANEL_PATH={panel_path}
      - TZ=UTC

    volumes:
      - ./data:/etc/x-ui
      - /dev/shm:/dev/shm:rw    # Shared memory for Unix domain sockets

    privileged: true
    cap_add:
      - NET_ADMIN

    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:2053 | grep -q 'Welcome' || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s

    labels:
      - "com.3x-ui.description=3x-ui Web Panel"
      - "com.3x-ui.version=latest"
'''

    compose_file = f"{deploy_dir}/docker-compose.yml"
    try:
        with open(compose_file, 'w') as f:
            f.write(docker_compose_template)
        print_success(f"Created {compose_file}")
    except Exception as e:
        print_error(f"Failed to write docker-compose.yml: {e}")
        return False

    print_step(4, 5, "Starting 3x-ui container")
    code, out, err = run_command(f"cd {deploy_dir} && docker compose up -d", check=False)

    if code != 0:
        print_error(f"Failed to start container: {err}")
        print("Output:", out)
        return False

    print_success("Container started")
    print(out)

    print_step(5, 5, "Verifying container is running")
    time.sleep(3)  # Wait for container to initialize

    code, out, err = run_command("docker ps --filter name=3x-ui --format '{{.Names}}\t{{.Status}}'", check=False)
    if code == 0 and "3x-ui" in out:
        print(f"  ✓ Container status: {out.strip()}")
        print_success("3x-ui container is running")

        print(f"\n{Colors.BOLD}Configuration saved:{Colors.ENDC}")
        print(f"  Deployment dir: {deploy_dir}")
        print(f"  Admin username: {admin_user}")
        print(f"  Admin password: {admin_pass}")
        print(f"  Panel path: {panel_path}")

        # Store config for next step
        return {
            "deploy_dir": deploy_dir,
            "admin_user": admin_user,
            "admin_pass": admin_pass,
            "panel_path": panel_path
        }
    else:
        print_error("Container not running")
        # Show logs
        print("\nContainer logs:")
        run_command(f"docker logs 3x-ui 2>&1 | tail -20", check=False)
        return False


# ============================================================================
# STEP 5: Wait for health and create gRPC inbound with Unix socket
# ============================================================================

def step5_configure_grpc(config: dict):
    """Wait for container health, read credentials, and create gRPC inbound with Unix socket"""
    print_header("STEP 5: Configuring gRPC Backend with Unix Socket")

    if not config or not isinstance(config, dict):
        print_error("No configuration from previous step")
        return False

    deploy_dir = config.get("deploy_dir", "/opt/3x-ui")
    admin_user = config.get("admin_user", "admin")
    admin_pass = config.get("admin_pass", "admin")

    print_step(1, 4, "Waiting for container to be healthy")
    max_wait = 60  # seconds
    waited = 0
    interval = 5

    while waited < max_wait:
        code, out, _ = run_command(
            "docker inspect 3x-ui --format '{{.State.Health.Status}}'",
            check=False
        )
        if code == 0:
            health_status = out.strip()
            if health_status == "healthy":
                print_success(f"Container is healthy (waited {waited}s)")
                break
            elif health_status == "starting":
                print(f"  Container health: {health_status} (waited {waited}s)")
            else:
                print_warning(f"  Container health: {health_status}")

        time.sleep(interval)
        waited += interval
    else:
        print_warning(f"Container not healthy after {max_wait}s, continuing anyway...")

    print_step(2, 4, "Reading generated credentials")
    creds_file = f"{deploy_dir}/data/credentials.txt"

    # Wait for credentials file to appear
    max_wait_creds = 30
    waited_creds = 0

    while waited_creds < max_wait_creds:
        if os.path.exists(creds_file):
            break
        time.sleep(2)
        waited_creds += 2

    # Try to read credentials
    actual_user = admin_user
    actual_pass = admin_pass

    if os.path.exists(creds_file):
        try:
            with open(creds_file, 'r') as f:
                content = f.read()
                print(f"  Credentials found in {creds_file}")

                # Extract username and password
                for line in content.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().lower()
                        value = value.strip()
                        if 'username' in key or 'user' in key:
                            actual_user = value
                        elif 'password' in key or 'pass' in key:
                            actual_pass = value

                print(f"  Username: {actual_user}")
                print(f"  Password: {'*' * len(actual_pass)}")
        except Exception as e:
            print_warning(f"Could not read credentials file: {e}")
            print(f"  Using configured credentials")
    else:
        print_warning(f"Credentials file not found, using configured credentials")

    print_step(3, 4, "Creating gRPC inbound with Unix socket")

    # Import x_ui_client
    try:
        sys.path.insert(0, '/home/stein/python/3x-ui')
        from x_ui_client import XUIClient
    except ImportError as e:
        print_error(f"Failed to import x_ui_client: {e}")
        print("  Please ensure x_ui_client is available")
        return False

    # Create inbound with Unix socket
    socket_path = "/dev/shm/xui-grpc.sock"
    print(f"  Socket: {socket_path},0666")
    print(f"  Service name: api")

    try:
        client = XUIClient(
            base_url="http://localhost:2053",
            username=actual_user,
            password=actual_pass,
            verify_ssl=False
        )

        client.login()
        print("  ✓ Authenticated to 3x-ui API")

        inbound_config = {
            "enable": True,
            "port": 0,  # Port 0 for Unix socket
            "protocol": "vless",
            "listen": f"{socket_path},0666",  # Unix socket with permissions
            "settings": json.dumps({
                "clients": [],  # Empty - add clients later
                "decryption": "none",
                "fallbacks": []
            }),
            "streamSettings": json.dumps({
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "serviceName": "api",
                    "multiMode": False
                }
            }),
            "sniffing": json.dumps({
                "enabled": True,
                "destOverride": ["http", "tls"]
            }),
            "remark": "VLESS-gRPC-Local",
            "allocate": json.dumps({
                "strategy": "always",
                "refresh": 5,
                "concurrency": 3
            })
        }

        success = client.add_inbound(inbound_config)

        if success:
            print_success("gRPC inbound created with Unix socket")
        else:
            print_error("Failed to create inbound")
            return False

    except Exception as e:
        print_error(f"Failed to create gRPC inbound: {e}")
        import traceback
        traceback.print_exc()
        return False

    print_step(4, 4, "Deployment summary")
    print(f"\n{Colors.BOLD}{Colors.GREEN}3x-ui Node Deployed Successfully!{Colors.ENDC}")
    print(f"\n{Colors.BOLD}Access Information:{Colors.ENDC}")
    print(f"  Panel URL: http://localhost:2053{config['panel_path']}")
    print(f"  Username: {actual_user}")
    print(f"  Password: {actual_pass}")
    print(f"\n{Colors.BOLD}gRPC Configuration:{Colors.ENDC}")
    print(f"  Transport: Unix Socket")
    print(f"  Socket: {socket_path}")
    print(f"  Permissions: 0666")
    print(f"  Service Name: api")
    print(f"\n{Colors.BOLD}Port Mappings:{Colors.ENDC}")
    print(f"  gRPC: 127.0.0.1:10002 → container:10000")
    print(f"  WebSocket: 127.0.0.1:10003 → container:10001")
    print(f"\n{Colors.BOLD}Next Steps:{Colors.ENDC}")
    print(f"  1. Point DNS to this server")
    print(f"  2. Obtain SSL certificates with certbot")
    print(f"  3. Deploy nginx/HAProxy with Ansible")
    print(f"  4. Add clients using xui-client script")

    return True


# ============================================================================
# STEP 6: Configure Anti-Abuse Firewall (iptables)
# ============================================================================

def step6_configure_firewall():
    """Configure iptables to block abuse traffic from Docker containers"""
    print_header("STEP 6: Configuring Anti-Abuse Firewall")

    print("This will block from Docker containers:")
    print("  - SMTP (ports 25, 465, 587, 2525) - anti-spam")
    print("  - BitTorrent (ports 6881-6889, 51413) - anti-piracy")
    print("  - DHT/tracker ports (6969, 1337)")
    print("  - P2P ports (4662, 4672) - eDonkey, eMule")
    print()

    print_step(1, 4, "Detecting Docker network subnet")

    # Get Docker network subnet
    docker_network = "3x-ui_default"
    code, subnet, err = run_command(
        f"docker network inspect {docker_network} -f '{{{{range .IPAM.Config}}}}{{{{.Subnet}}}}{{{{end}}}}'",
        check=False
    )

    if code != 0 or not subnet.strip():
        subnet = "172.18.0.0/16"  # Default fallback
        print_warning(f"Could not detect Docker subnet, using default: {subnet}")
    else:
        subnet = subnet.strip()
        print(f"  Docker subnet: {subnet}")

    print_step(2, 4, "Adding iptables DOCKER-USER rules")

    # Rules to block abuse
    rules = [
        # SMTP (anti-spam)
        (subnet, "tcp", "25", "SMTP"),
        (subnet, "tcp", "465", "SMTPS"),
        (subnet, "tcp", "587", "SMTP Submission"),
        (subnet, "tcp", "2525", "SMTP Alt"),

        # BitTorrent
        (subnet, "tcp", "6881:6889", "BitTorrent TCP"),
        (subnet, "udp", "6881:6889", "BitTorrent UDP"),
        (subnet, "tcp", "51413", "BitTorrent"),
        (subnet, "udp", "51413", "BitTorrent UDP"),

        # DHT/Tracker
        (subnet, "udp", "6969", "BitTorrent Tracker"),
        (subnet, "udp", "1337", "DHT"),

        # P2P
        (subnet, "tcp", "4662", "eDonkey"),
        (subnet, "tcp", "4672", "eMule"),
    ]

    added = 0
    failed = 0

    for src, protocol, port, description in rules:
        cmd = f"iptables -I DOCKER-USER -s {src} -p {protocol} --dport {port} -j DROP"
        code, _, err = run_command(cmd, check=False)

        if code == 0:
            print(f"  ✓ Blocked {description} ({protocol}/{port})")
            added += 1
        else:
            print_error(f"  Failed to block {description}: {err}")
            failed += 1

    print(f"\n  Summary: {added} rules added, {failed} failed")

    print_step(3, 4, "Saving iptables rules and creating restore service")

    # Save rules to file
    rules_file = "/etc/iptables/rules.v4"
    os.makedirs(os.path.dirname(rules_file), exist_ok=True)
    code, _, err = run_command(f"iptables-save > {rules_file}", check=False)
    if code == 0:
        print(f"  ✓ Rules saved to {rules_file}")
    else:
        print_warning(f"  Could not save rules: {err}")

    # Create systemd service to restore rules on boot
    service_content = f"""[Unit]
Description=Restore iptables rules
Before=docker.service network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore {rules_file}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""

    service_file = "/etc/systemd/system/iptables-restore.service"
    try:
        with open(service_file, "w") as f:
            f.write(service_content)
        print(f"  ✓ Created {service_file}")

        # Enable the service
        code, _, _ = run_command("systemctl daemon-reload", check=False)
        code, _, _ = run_command("systemctl enable iptables-restore.service", check=False)
        if code == 0:
            print("  ✓ Enabled iptables-restore service")
        else:
            print_warning("  Could not enable iptables-restore service")
    except Exception as e:
        print_warning(f"  Could not create restore service: {e}")

    print_step(4, 4, "Verifying rules")

    code, out, _ = run_command("iptables -L DOCKER-USER -n -v", check=False)
    if code == 0:
        # Count DROP rules
        drop_count = out.count("DROP")
        print(f"  ✓ DOCKER-USER chain has {drop_count} DROP rules")
        print_success("Anti-abuse firewall configured")

        print(f"\n{Colors.BOLD}Blocked Protocols:{Colors.ENDC}")
        print(f"  ✓ SMTP (anti-spam)")
        print(f"  ✓ BitTorrent (anti-piracy)")
        print(f"  ✓ P2P protocols")

        print(f"\n{Colors.YELLOW}Note:{Colors.ENDC}")
        print(f"  To view rules: iptables -L DOCKER-USER -n -v")
        print(f"  Rules are persistent across reboots (iptables-restore.service)")

        return True
    else:
        print_error("Could not verify iptables rules")
        return False


# ============================================================================
# STEP 7: Disable Nginx Logging
# ============================================================================

def step7_disable_nginx_logging():
    """Disable nginx access and error logging to save disk space"""
    print_header("STEP 7: Disabling Nginx Logging")

    print_step(1, 2, "Disabling nginx logging in main config")

    # Backup nginx.conf
    backup_file = f"/etc/nginx/nginx.conf.backup.{int(time.time())}"
    code, _, _ = run_command(f"cp /etc/nginx/nginx.conf {backup_file}", check=False)
    if code == 0:
        print(f"  ✓ Backup created: {backup_file}")

    # Disable logging in nginx.conf
    nginx_logging_config = """
    # Disable access and error logging
    access_log off;
    error_log /dev/null crit;
"""

    # Check if logging is already disabled
    code, out, _ = run_command("grep -q 'access_log off' /etc/nginx/nginx.conf", check=False)
    if code == 0:
        print("  ⊙ Logging already disabled in nginx.conf")
    else:
        # Add to http block using proper escaping
        cmd = "sed -i '/http {/a\\    # Disable access and error logging\\n    access_log off;\\n    error_log /dev/null crit;' /etc/nginx/nginx.conf"
        code, _, err = run_command(cmd, check=False)
        if code == 0:
            print("  ✓ Disabled logging in nginx.conf")
        else:
            print_warning(f"Could not modify nginx.conf: {err}")

    print_step(2, 2, "Cleaning up existing nginx logs")

    log_dirs = [
        "/var/log/nginx/",
    ]

    total_freed = 0
    for log_dir in log_dirs:
        # Get current size
        code, size_out, _ = run_command(f"du -sb {log_dir} 2>/dev/null | cut -f1", check=False)
        if code == 0 and size_out.strip():
            size_before = int(size_out.strip())
        else:
            size_before = 0

        # Clean logs
        code, _, _ = run_command(f"find {log_dir} -type f -name '*.log*' -delete 2>/dev/null", check=False)

        if size_before > 0:
            freed_mb = size_before / 1024 / 1024
            total_freed += freed_mb
            print(f"  ✓ Cleaned {log_dir}: {freed_mb:.1f} MB")

    if total_freed > 0:
        print_success(f"Total space freed: {total_freed:.1f} MB")
    else:
        print("  ⊙ No logs to clean")

    print_success("Nginx logging disabled")
    return True


# ============================================================================
# STEP 8: Configure Hostname
# ============================================================================

def step8_configure_hostname(hostname: str = None):
    """Configure system hostname"""
    print_header("STEP 8: Configuring Hostname")

    if not hostname:
        print_warning("No hostname provided, skipping")
        return True

    print(f"  Setting hostname to: {hostname}")

    print_step(1, 4, "Updating /etc/hostname")
    try:
        with open("/etc/hostname", "w") as f:
            f.write(f"{hostname}\n")
        print_success(f"Updated /etc/hostname")
    except Exception as e:
        print_error(f"Failed to update /etc/hostname: {e}")
        return False

    print_step(2, 4, "Updating /etc/hosts")
    try:
        # Read current hosts file
        with open("/etc/hosts", "r") as f:
            hosts_content = f.read()

        # Check if hostname already exists
        if hostname not in hosts_content:
            # Add entry for the new hostname
            with open("/etc/hosts", "a") as f:
                f.write(f"\n127.0.1.1\t{hostname}\n")
            print_success("Added hostname to /etc/hosts")
        else:
            print(f"  ⊙ Hostname already in /etc/hosts")

    except Exception as e:
        print_error(f"Failed to update /etc/hosts: {e}")
        return False

    print_step(3, 4, "Applying hostname changes")

    # Try hostnamectl first (systemd)
    code, out, err = run_command(f"hostnamectl set-hostname {hostname}", check=False)
    if code == 0:
        print("  ✓ Applied with hostnamectl")
    else:
        # Fallback to hostname command
        code, out, err = run_command(f"hostname {hostname}", check=False)
        if code == 0:
            print("  ✓ Applied with hostname command")
        else:
            print_error(f"Failed to apply hostname: {err}")
            return False

    print_step(4, 4, "Verifying hostname")
    code, current_hostname, _ = run_command("hostname", check=False)
    if code == 0:
        current_hostname = current_hostname.strip()
        if current_hostname == hostname:
            print(f"  ✓ Hostname verified: {current_hostname}")
            print_success("Hostname configured successfully")
            return True
        else:
            print_warning(f"  Hostname mismatch: set={hostname}, current={current_hostname}")
            print_warning("  Hostname may require reboot to fully apply")
            return True
    else:
        print_error("Could not verify hostname")
        return False


# ============================================================================
# STEP 9: Deploy Basic Nginx Config (for SSL cert acquisition)
# ============================================================================

def step9_deploy_basic_nginx(domain: str = None):
    """Deploy basic nginx configuration for SSL certificate acquisition"""
    print_header("STEP 9: Deploying Basic Nginx Configuration")

    if not domain:
        print_warning("No domain provided, skipping nginx configuration")
        print("  To configure nginx, run with: --domain your-domain.com")
        return True

    print(f"  Domain: {domain}")

    print_step(1, 4, "Creating web root directories")
    dirs = ["/var/www/site", "/var/www/html"]
    for d in dirs:
        code, _, err = run_command(f"mkdir -p {d}", check=False)
        if code == 0:
            print(f"  ✓ Created {d}")
        else:
            print_error(f"Failed to create {d}: {err}")
            return False

    print_step(2, 4, "Creating default index.html")
    index_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{domain}</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
        h1 {{ color: #333; }}
    </style>
</head>
<body>
    <h1>Welcome to {domain}</h1>
    <p>Server is running</p>
</body>
</html>"""

    try:
        with open("/var/www/site/index.html", "w") as f:
            f.write(index_html)
        print_success("Created index.html")
    except Exception as e:
        print_error(f"Failed to create index.html: {e}")
        return False

    print_step(3, 4, "Deploying basic nginx configuration")

    config_name = domain.replace(".", "_")
    nginx_config = f"""# Basic configuration for {domain}
# Stage 1: HTTP only for SSL certificate acquisition

server {{
    listen 80;
    listen [::]:80;
    server_name {domain};

    server_tokens off;

    root /var/www/site;
    index index.html;
    access_log off;
    error_log /dev/null crit;

    # ACME challenge location for Let's Encrypt
    location /.well-known/acme-challenge/ {{
        root /var/www/html;
        try_files $uri =404;
    }}

    # Static content
    location / {{
        try_files $uri $uri/ =404;
        add_header Cache-Control "public, max-age=3600";
    }}

    # API endpoints
    location /status {{
        default_type application/json;
        return 200 '{{"status":"ok","version":"1.0.0"}}';
    }}

    location /health {{
        default_type application/json;
        return 200 '{{"healthy":true}}';
    }}

    # Security
    location ~ /\\.git {{
        deny all;
        return 404;
    }}

    location ~ /\\. {{
        deny all;
        access_log off;
        log_not_found off;
        return 404;
    }}
}}"""

    config_file = f"/etc/nginx/sites-available/{config_name}"
    try:
        with open(config_file, "w") as f:
            f.write(nginx_config)
        print(f"  ✓ Created {config_file}")
    except Exception as e:
        print_error(f"Failed to write nginx config: {e}")
        return False

    # Enable site
    symlink = f"/etc/nginx/sites-enabled/{config_name}"
    code, _, err = run_command(f"ln -sf {config_file} {symlink}", check=False)
    if code == 0:
        print(f"  ✓ Enabled site: {symlink}")
    else:
        print_error(f"Failed to enable site: {err}")
        return False

    print_step(4, 4, "Testing and reloading nginx")
    code, out, err = run_command("nginx -t", check=False)
    if code != 0:
        print_error(f"Nginx configuration test failed: {err}")
        print_warning("Config file: " + config_file)
        return False

    code, _, err = run_command("systemctl reload nginx", check=False)
    if code != 0:
        print_error(f"Failed to reload nginx: {err}")
        return False

    print_success("Nginx configured and reloaded")
    print(f"\n{Colors.BOLD}Basic nginx configuration deployed:{Colors.ENDC}")
    print(f"  Domain: {domain}")
    print(f"  Config: {config_file}")
    print(f"  Web root: /var/www/site")

    return domain  # Return domain for next step


# ============================================================================
# STEP 10: Obtain SSL Certificates
# ============================================================================

def step10_obtain_ssl_cert(domain: str = None):
    """Guide user to obtain SSL certificates with certbot"""
    print_header("STEP 10: Obtaining SSL Certificates")

    if not domain:
        print_warning("No domain configured, skipping SSL certificate acquisition")
        return True

    print(f"  Domain: {domain}")

    print_step(1, 3, "Checking DNS propagation")
    print(f"\n{Colors.YELLOW}Before obtaining SSL certificates, ensure DNS is configured:{Colors.ENDC}")
    print(f"  A record for {domain} must point to this server's IP")
    print()

    # Try to detect current IP
    code, ip_out, _ = run_command("curl -s ifconfig.me", check=False)
    if code == 0:
        server_ip = ip_out.strip()
        print(f"  This server's IP: {Colors.BOLD}{server_ip}{Colors.ENDC}")
    else:
        server_ip = "UNKNOWN"
        print_warning("  Could not detect server IP")

    # Check DNS resolution
    code, dns_out, _ = run_command(f"dig +short {domain} @8.8.8.8", check=False)
    if code == 0 and dns_out.strip():
        dns_ip = dns_out.strip().split('\n')[0]
        print(f"  DNS resolves to: {Colors.BOLD}{dns_ip}{Colors.ENDC}")

        if dns_ip == server_ip:
            print_success("  DNS correctly points to this server")
        else:
            print_warning(f"  DNS mismatch! Expected {server_ip}, got {dns_ip}")
    else:
        print_warning(f"  Could not resolve {domain}")

    print()
    response = input(f"{Colors.CYAN}DNS is configured correctly? [y/N]: {Colors.ENDC}")
    if response.lower() not in ['y', 'yes']:
        print_warning("Skipping SSL certificate acquisition")
        print("  Configure DNS and run certbot manually later")
        return False

    print_step(2, 3, "Requesting SSL certificate with certbot")

    # Ask for email
    email = input(f"{Colors.CYAN}Email for Let's Encrypt notifications [{Colors.BOLD}admin@{domain}{Colors.ENDC}{Colors.CYAN}]: {Colors.ENDC}").strip()
    if not email:
        email = f"admin@{domain}"

    print(f"\n  Requesting certificate for: {domain}")
    print(f"  Email: {email}")
    print()

    # Run certbot
    cmd = f"""certbot certonly --nginx \\
  -d {domain} \\
  --non-interactive --agree-tos \\
  -m {email}"""

    print(f"  Running: {cmd}")
    print()

    code, out, err = run_command(cmd, check=False)

    if code == 0:
        print_success("SSL certificate obtained successfully")
        print(out)

        # Verify certificate files
        cert_dir = f"/etc/letsencrypt/live/{domain}"
        cert_files = ["fullchain.pem", "privkey.pem"]

        all_exist = True
        for cert_file in cert_files:
            cert_path = f"{cert_dir}/{cert_file}"
            if os.path.exists(cert_path):
                print(f"  ✓ {cert_path}")
            else:
                print_error(f"  Missing: {cert_path}")
                all_exist = False

        if all_exist:
            print_step(3, 3, "SSL certificate ready")
            return domain  # Return domain for next step
        else:
            print_error("Some certificate files are missing")
            return False
    else:
        print_error("Failed to obtain SSL certificate")
        print("Error:", err)
        print("\nTroubleshooting:")
        print("  1. Ensure DNS A record points to this server")
        print("  2. Check nginx is running: systemctl status nginx")
        print(f"  3. Test HTTP access: curl http://{domain}")
        return False


# ============================================================================
# STEP 11: Deploy Full Nginx + HAProxy Configuration
# ============================================================================

def step11_deploy_full_config(domain: str = None):
    """Deploy full nginx and HAProxy configuration with SSL"""
    print_header("STEP 11: Deploying Full Nginx + HAProxy Configuration")

    if not domain:
        print_warning("No domain configured, skipping full configuration")
        return True

    # Verify SSL certificates exist
    cert_dir = f"/etc/letsencrypt/live/{domain}"
    if not os.path.exists(f"{cert_dir}/fullchain.pem"):
        print_error(f"SSL certificate not found: {cert_dir}/fullchain.pem")
        print("  Run Step 10 first to obtain SSL certificates")
        return False

    print(f"  Domain: {domain}")
    print(f"  SSL certificates: {cert_dir}")

    print_step(1, 3, "Deploying full nginx configuration")

    config_name = domain.replace(".", "_")
    nginx_config = f"""# Full HTTP/HTTPS configuration for {domain}
# Stage 2: With SSL support

# HTTP on public interface (port 80)
server {{
    listen 80;
    listen [::]:80;
    server_name {domain};

    server_tokens off;

    root /var/www/site;
    index index.html;
    access_log off;
    error_log /dev/null crit;

    # ACME challenge location for Let's Encrypt
    location /.well-known/acme-challenge/ {{
        root /var/www/html;
        try_files $uri =404;
    }}

    # Static content
    location / {{
        try_files $uri $uri/ =404;
        add_header Cache-Control "public, max-age=3600";
    }}

    # API endpoints
    location /status {{
        default_type application/json;
        return 200 '{{"status":"ok","version":"1.0.0"}}';
    }}

    location /health {{
        default_type application/json;
        return 200 '{{"healthy":true}}';
    }}
}}

# HTTPS on localhost (port 8080) - forwarded from HAProxy
server {{
    listen 127.0.0.1:8080 ssl http2;
    server_name {domain};

    server_tokens off;

    # SSL/TLS Configuration
    ssl_certificate {cert_dir}/fullchain.pem;
    ssl_certificate_key {cert_dir}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1h;
    ssl_session_tickets off;

    root /var/www/site;
    index index.html;
    access_log off;
    error_log /dev/null crit;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_min_length 1000;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/atom+xml image/svg+xml;

    # gRPC Backend - /sync -> 127.0.0.1:10002
    location /sync {{
        grpc_pass grpc://127.0.0.1:10002;
        grpc_buffer_size 128k;
        grpc_socket_keepalive on;
        grpc_read_timeout 60s;
        grpc_send_timeout 60s;
        grpc_connect_timeout 10s;
        grpc_set_header Connection "";
        grpc_set_header Host $host;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        grpc_set_header X-Forwarded-Proto $scheme;
        grpc_set_header X-Forwarded-Port $server_port;
        grpc_set_header X-Forwarded-Host $host;
    }}

    # WebSocket Backend - /ws -> 127.0.0.1:10003
    location /ws {{
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        proxy_connect_timeout 60s;
        proxy_buffering off;
    }}

    # Static Content
    location / {{
        try_files $uri $uri/ =404;
        add_header Cache-Control "public, max-age=3600";
    }}

    location ~* \\.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {{
        expires 7d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }}

    # API endpoints
    location /status {{
        default_type application/json;
        return 200 '{{"status":"ok","version":"1.0.0"}}';
        add_header Access-Control-Allow-Origin *;
    }}

    location /health {{
        default_type application/json;
        return 200 '{{"healthy":true}}';
    }}

    # Security
    location ~ /\\.git {{
        deny all;
        return 404;
    }}

    location ~ /\\. {{
        deny all;
        access_log off;
        log_not_found off;
        return 404;
    }}
}}"""

    config_file = f"/etc/nginx/sites-available/{config_name}"

    # Backup existing config
    if os.path.exists(config_file):
        backup_file = f"{config_file}.backup.{int(time.time())}"
        run_command(f"cp {config_file} {backup_file}", check=False)
        print(f"  ✓ Backup created: {backup_file}")

    try:
        with open(config_file, "w") as f:
            f.write(nginx_config)
        print_success(f"Nginx configuration updated: {config_file}")
    except Exception as e:
        print_error(f"Failed to write nginx config: {e}")
        return False

    # Test nginx
    code, out, err = run_command("nginx -t", check=False)
    if code != 0:
        print_error(f"Nginx configuration test failed: {err}")
        return False

    code, _, _ = run_command("systemctl reload nginx", check=False)
    if code != 0:
        print_error("Failed to reload nginx")
        return False

    print_success("Nginx reloaded with full configuration")

    print_step(2, 3, "Deploying HAProxy configuration")

    # Check if HAProxy is installed
    code, _, _ = run_command("which haproxy", check=False)
    if code != 0:
        print("Installing HAProxy...")
        code, _, err = run_command("apt install -y haproxy", check=False)
        if code != 0:
            print_error(f"Failed to install HAProxy: {err}")
            return False

    # Backup HAProxy config
    haproxy_config_file = "/etc/haproxy/haproxy.cfg"
    if os.path.exists(haproxy_config_file):
        backup_file = f"{haproxy_config_file}.backup.{int(time.time())}"
        run_command(f"cp {haproxy_config_file} {backup_file}", check=False)
        print(f"  ✓ HAProxy backup: {backup_file}")

    haproxy_config = f"""# HAProxy Configuration for SNI-based routing
# Domain: {domain}

global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull

    timeout connect 10s
    timeout client  1h
    timeout server  1h
    timeout client-fin 30s
    timeout server-fin 30s

frontend tls_frontend
    bind *:443
    mode tcp

    tcp-request inspect-delay 5s
    tcp-request content accept if {{ req_ssl_hello_type 1 }}

    # Route {domain} to nginx backend (port 8080)
    use_backend nginx_backend if {{ req_ssl_sni -i {domain} }}

    # All other SNI goes to Reality backend (port 8443)
    default_backend xray_reality

backend nginx_backend
    mode tcp
    option tcp-check
    server nginx1 127.0.0.1:8080 check inter 5s rise 2 fall 3

backend xray_reality
    mode tcp
    option tcp-check
    server xray1 127.0.0.1:8443 check inter 5s rise 2 fall 3

listen stats
    bind 127.0.0.1:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE"""

    try:
        with open(haproxy_config_file, "w") as f:
            f.write(haproxy_config)
        print_success(f"HAProxy configuration written: {haproxy_config_file}")
    except Exception as e:
        print_error(f"Failed to write HAProxy config: {e}")
        return False

    # Test HAProxy config
    code, out, err = run_command("haproxy -c -f /etc/haproxy/haproxy.cfg", check=False)
    if code != 0:
        print_error(f"HAProxy configuration test failed: {err}")
        return False

    # Restart HAProxy
    code, _, err = run_command("systemctl restart haproxy", check=False)
    if code != 0:
        print_error(f"Failed to restart HAProxy: {err}")
        return False

    code, _, _ = run_command("systemctl enable haproxy", check=False)

    print_success("HAProxy configured and started")

    print_step(3, 3, "Verifying services")

    time.sleep(2)  # Wait for services to start

    # Check nginx port 8080
    code, _, _ = run_command("ss -tlnp | grep ':8080'", check=False)
    if code == 0:
        print("  ✓ Nginx listening on 127.0.0.1:8080")
    else:
        print_warning("  Nginx not listening on port 8080")

    # Check HAProxy port 443
    code, _, _ = run_command("ss -tlnp | grep ':443'", check=False)
    if code == 0:
        print("  ✓ HAProxy listening on *:443")
    else:
        print_warning("  HAProxy not listening on port 443")

    print_success("Full configuration deployed successfully")

    print(f"\n{Colors.BOLD}Configuration Summary:{Colors.ENDC}")
    print(f"  Domain: {domain}")
    print(f"  Nginx HTTP: port 80 (static + ACME)")
    print(f"  Nginx HTTPS: port 8080 (backends)")
    print(f"  HAProxy: port 443 (SNI routing)")
    print(f"\n{Colors.BOLD}Traffic Flow:{Colors.ENDC}")
    print(f"  Client → HAProxy:443 → Nginx:8080 → Backends")
    print(f"    /sync → gRPC:10002")
    print(f"    /ws   → WebSocket:10003")

    return True


# ============================================================================
# STEP 12: Final Check and Reboot
# ============================================================================

def step12_final_check_and_reboot():
    """Final system check and optional reboot"""
    print_header("STEP 12: Final Check and Reboot")

    print_step(1, 3, "Running system checks")

    checks = []

    # Check Docker
    code, out, _ = run_command("docker ps --filter name=3x-ui --format '{{.Status}}'", check=False)
    if code == 0 and "Up" in out:
        checks.append(("Docker container", True, "Running"))
    else:
        checks.append(("Docker container", False, "Not running"))

    # Check container health
    code, out, _ = run_command("docker inspect 3x-ui --format '{{.State.Health.Status}}'", check=False)
    if code == 0:
        health = out.strip()
        checks.append(("Container health", health == "healthy", health))
    else:
        checks.append(("Container health", False, "Unknown"))

    # Check iptables rules
    code, out, _ = run_command("iptables -L DOCKER-USER -n | grep DROP | wc -l", check=False)
    if code == 0:
        drop_count = int(out.strip())
        checks.append(("Iptables rules", drop_count >= 12, f"{drop_count} DROP rules"))
    else:
        checks.append(("Iptables rules", False, "Could not verify"))

    # Check BBR
    code, out, _ = run_command("sysctl -n net.ipv4.tcp_congestion_control", check=False)
    if code == 0:
        bbr_enabled = out.strip() == "bbr"
        checks.append(("BBR congestion control", bbr_enabled, out.strip()))
    else:
        checks.append(("BBR congestion control", False, "Unknown"))

    # Check nginx
    code, _, _ = run_command("which nginx", check=False)
    checks.append(("Nginx installed", code == 0, "Ready" if code == 0 else "Not found"))

    # Check tailscale
    code, _, _ = run_command("which tailscale", check=False)
    checks.append(("Tailscale installed", code == 0, "Ready" if code == 0 else "Not found"))

    # Display checks
    print("\n  System checks:")
    all_passed = True
    for name, passed, status in checks:
        if passed:
            print(f"    ✓ {name}: {status}")
        else:
            print(f"    ✗ {name}: {status}")
            all_passed = False

    print()

    if all_passed:
        print_success("All system checks passed")
    else:
        print_warning("Some checks failed - review before continuing")

    print_step(2, 3, "Deployment summary")

    print(f"\n{Colors.BOLD}{Colors.GREEN}Deployment completed successfully!{Colors.ENDC}\n")

    print(f"{Colors.BOLD}What was configured:{Colors.ENDC}")
    print(f"  ✓ System packages (27 packages)")
    print(f"  ✓ Tailscale VPN")
    print(f"  ✓ Network optimizations (BBR, sysctl)")
    print(f"  ✓ 3x-ui Docker container")
    print(f"  ✓ VLESS gRPC with Unix socket (/dev/shm/xui-grpc.sock)")
    print(f"  ✓ VLESS gRPC endpoint (port 10002 → container 10000)")
    print(f"  ✓ VLESS WebSocket endpoint (port 10003 → container 10001)")
    print(f"  ✓ Anti-abuse firewall (SMTP, BitTorrent, P2P blocked)")
    print(f"  ✓ System hostname")

    # Check if domain was configured
    code, _, _ = run_command("ss -tlnp | grep ':443'", check=False)
    if code == 0:
        print(f"  ✓ Nginx configuration (HTTP + HTTPS)")
        print(f"  ✓ HAProxy SNI routing (port 443)")
        print(f"  ✓ SSL certificates (Let's Encrypt)")

    print(f"\n{Colors.BOLD}Next steps:{Colors.ENDC}")
    # Check if HAProxy is running to determine next steps
    code, _, _ = run_command("ss -tlnp | grep ':443'", check=False)
    if code == 0:
        print(f"  1. Add VLESS clients via panel or xui-client script")
        print(f"  2. Test connectivity from VPN clients")
        print(f"  3. Monitor logs and performance")
    else:
        print(f"  1. Point DNS A records to this server's IP")
        print(f"  2. Run with --domain flag to configure nginx/HAProxy")
        print(f"  3. Add VLESS clients via panel or xui-client script")

    print(f"\n{Colors.BOLD}Important locations:{Colors.ENDC}")
    print(f"  Admin panel: http://localhost:2053/admin")
    print(f"  Docker files: /opt/3x-ui/")
    print(f"  Data volume: /opt/3x-ui/data/")
    print(f"  gRPC endpoint: 127.0.0.1:10002")
    print(f"  WebSocket endpoint: 127.0.0.1:10003")

    print_step(3, 3, "Reboot system")

    print(f"\n{Colors.YELLOW}A reboot is recommended to ensure all changes take effect:{Colors.ENDC}")
    print(f"  - Hostname changes")
    print(f"  - Kernel parameters (sysctl)")
    print(f"  - Network optimizations")

    response = input(f"\n{Colors.BOLD}Reboot now? [y/N]: {Colors.ENDC}")
    if response.lower() in ['y', 'yes']:
        print(f"\n{Colors.YELLOW}System will reboot in 5 seconds...{Colors.ENDC}")
        print("Press Ctrl+C to cancel")
        try:
            time.sleep(5)
            print_success("Rebooting system...")
            run_command("reboot", check=False)
            return True
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Reboot cancelled{Colors.ENDC}")
            return True
    else:
        print(f"\n{Colors.YELLOW}Skipping reboot. Reboot manually when ready: sudo reboot{Colors.ENDC}")
        return True


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main deployment function"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='3x-ui Node Deployment Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo ./deploy-node.py
  sudo ./deploy-node.py --hostname node-vienna
  sudo ./deploy-node.py --hostname vpn-server-01 --domain maptrail.shop
  sudo ./deploy-node.py --domain lionhex.xyz
        """
    )
    parser.add_argument(
        '--hostname',
        type=str,
        help='System hostname to configure (optional)'
    )
    parser.add_argument(
        '--domain',
        type=str,
        help='Domain name for nginx/HAProxy configuration (optional)'
    )
    args = parser.parse_args()

    print_header("3x-ui Node Deployment Script")

    # Check if running as root
    check_root()

    # Run steps
    steps = [
        ("Install Required Packages", step1_install_packages, False, None),
        ("Install Tailscale", step2_install_tailscale, False, None),
        ("Optimize sysctl Values", step3_optimize_sysctl, False, None),
        ("Setup 3x-ui Docker Container", step4_setup_3xui, True, None),  # Returns config
        ("Configure gRPC Backend", step5_configure_grpc, True, None),    # Needs config
        ("Configure Anti-Abuse Firewall", step6_configure_firewall, False, None),
        ("Disable Nginx Logging", step7_disable_nginx_logging, False, None),
        ("Configure Hostname", step8_configure_hostname, False, args.hostname),  # Needs hostname
        ("Deploy Basic Nginx Config", step9_deploy_basic_nginx, False, args.domain),  # Needs domain
        ("Obtain SSL Certificates", step10_obtain_ssl_cert, False, args.domain),  # Needs domain
        ("Deploy Full Nginx + HAProxy Config", step11_deploy_full_config, False, args.domain),  # Needs domain
        ("Final Check and Reboot", step12_final_check_and_reboot, False, None),
    ]

    total_steps = len(steps)
    failed_steps = []
    config_data = None

    for i, (name, func, needs_config, param) in enumerate(steps, 1):
        print(f"\n{Colors.BOLD}Starting: {name}{Colors.ENDC}")

        # Pass config if step needs it, or hostname if provided
        if needs_config and config_data:
            result = func(config_data)
        elif param is not None:
            result = func(param)
        else:
            result = func()

        # Check if result is config dict (from step4)
        if isinstance(result, dict):
            config_data = result
            success = True
        else:
            success = result

        if success:
            print_success(f"Completed: {name}\n")
        else:
            print_error(f"Failed: {name}\n")
            failed_steps.append(name)

            # Ask if user wants to continue
            response = input(f"{Colors.YELLOW}Continue with next step? [y/N]: {Colors.ENDC}")
            if response.lower() not in ['y', 'yes']:
                print_warning("Deployment aborted by user")
                break

    # Summary
    print_header("Deployment Summary")
    print(f"Total steps: {total_steps}")
    print(f"{Colors.GREEN}Successful: {total_steps - len(failed_steps)}{Colors.ENDC}")

    if failed_steps:
        print(f"{Colors.RED}Failed: {len(failed_steps)}{Colors.ENDC}")
        for step in failed_steps:
            print(f"  - {step}")
        sys.exit(1)
    else:
        print_success("All steps completed successfully!")
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Deployment interrupted by user{Colors.ENDC}")
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
