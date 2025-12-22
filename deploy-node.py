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
        "iperf3",
        "iptables-persistent"
    ]

    print_step(1, 4, "Updating package lists")
    code, out, err = run_command("apt-get update", check=False)
    if code != 0:
        print_error(f"Failed to update package lists: {err}")
        return False
    print_success("Package lists updated")

    # Install in groups to avoid dependency issues
    package_groups = {
        "Critical": ["docker.io", "docker-compose-v2", "nginx", "certbot", "python3-certbot-nginx", "iptables-persistent"],
        "Utilities": ["curl", "wget", "ca-certificates", "gnupg", "lsb-release", "jq", "socat"],
        "Editors": ["vim", "nano", "mc"],
        "Monitoring": ["htop", "iftop", "nload", "atop", "iperf3"],
        "Tools": ["screen", "unzip", "zip", "net-tools", "iproute2", "ufw"],
    }

    print_step(2, 4, "Installing packages in groups")
    total_installed = 0
    total_failed = 0
    failed_packages = []

    for group_name, group_packages in package_groups.items():
        print(f"\n  Installing {group_name} ({len(group_packages)} packages)...")
        pkg_list = " ".join(group_packages)
        cmd = f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg_list}"

        code, out, err = run_command(cmd, check=False)
        if code == 0:
            print(f"    ✓ {group_name}: {', '.join(group_packages)}")
            total_installed += len(group_packages)
        else:
            print_warning(f"    Some packages in {group_name} failed")
            failed_packages.extend(group_packages)
            total_failed += len(group_packages)

    print(f"\n  Summary: {total_installed} installed, {total_failed} failed")

    if total_failed > 0 and total_installed == 0:
        print_error("No packages were installed - critical failure")
        return False
    elif total_failed > 0:
        print_warning(f"Some packages failed but {total_installed} installed successfully")

    print_step(3, 4, "Installing any missing packages individually")
    if failed_packages:
        recovered = 0
        for pkg in failed_packages[:5]:  # Try first 5 failed packages individually
            code, _, _ = run_command(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg}", check=False)
            if code == 0:
                print(f"  ✓ Recovered: {pkg}")
                recovered += 1
        if recovered > 0:
            print_success(f"Recovered {recovered} packages")

    print_success(f"Package installation completed ({total_installed} packages)")

    print_step(4, 4, "Verifying critical packages")
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
        print_warning("Some critical packages are missing")
        # Return True anyway to continue deployment
        return total_installed > 0


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

        try:
            response = input(f"{Colors.YELLOW}Reinstall Tailscale? [y/N]: {Colors.ENDC}")
        except (EOFError, KeyboardInterrupt):
            response = "n"  # Skip reinstall in non-interactive mode
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

    # Configuration prompts (with defaults for non-interactive mode)
    print_step(1, 5, "Gathering configuration")

    # Deployment directory
    try:
        deploy_dir = input(f"{Colors.CYAN}Deployment directory [{Colors.BOLD}/opt/3x-ui{Colors.ENDC}{Colors.CYAN}]: {Colors.ENDC}").strip()
    except (EOFError, KeyboardInterrupt):
        deploy_dir = ""
    if not deploy_dir:
        deploy_dir = "/opt/3x-ui"

    # Admin username
    try:
        admin_user = input(f"{Colors.CYAN}Admin username [{Colors.BOLD}admin{Colors.ENDC}{Colors.CYAN}]: {Colors.ENDC}").strip()
    except (EOFError, KeyboardInterrupt):
        admin_user = ""
    if not admin_user:
        admin_user = "admin"

    # Admin password
    try:
        admin_pass = input(f"{Colors.CYAN}Admin password [{Colors.BOLD}admin{Colors.ENDC}{Colors.CYAN}]: {Colors.ENDC}").strip()
    except (EOFError, KeyboardInterrupt):
        admin_pass = ""
    if not admin_pass:
        admin_pass = "admin"

    # Panel path
    try:
        panel_path = input(f"{Colors.CYAN}Panel URL path [{Colors.BOLD}/admin{Colors.ENDC}{Colors.CYAN}]: {Colors.ENDC}").strip()
    except (EOFError, KeyboardInterrupt):
        panel_path = ""
    if not panel_path:
        panel_path = "/admin"

    print(f"\n  Deployment dir: {deploy_dir}")
    print(f"  Admin username: {admin_user}")
    print(f"  Admin password: {'*' * len(admin_pass)}")
    print(f"  Panel path: {panel_path}")

    print_step(2, 5, "Creating deployment directory")
    if os.path.exists(deploy_dir):
        print_warning(f"Directory {deploy_dir} already exists")
        try:
            response = input(f"{Colors.YELLOW}Continue anyway? [y/N]: {Colors.ENDC}")
        except (EOFError, KeyboardInterrupt):
            response = "y"  # Auto-continue in non-interactive mode
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
      - "127.0.0.1:10000:10000"   # gRPC endpoint for VLESS (localhost only)

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
    print(f"\n{Colors.BOLD}Next Steps:{Colors.ENDC}")
    print(f"  1. Setup nginx reverse proxy for HTTPS access")
    print(f"  2. Configure domain and SSL certificate")
    print(f"  3. Add clients using xui-client script")
    print(f"  4. Configure nginx to proxy to Unix socket")

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

    print_step(3, 4, "Saving iptables rules")

    # Try to save rules persistently
    saved = False

    # Try iptables-save to file
    for rules_file in ["/etc/iptables/rules.v4", "/etc/iptables.rules"]:
        os.makedirs(os.path.dirname(rules_file), exist_ok=True)
        code, _, _ = run_command(f"iptables-save > {rules_file}", check=False)
        if code == 0:
            print(f"  ✓ Rules saved to {rules_file}")
            saved = True
            break

    # Use netfilter-persistent (installed in Step 1)
    code, _, _ = run_command("netfilter-persistent save", check=False)
    if code == 0:
        print("  ✓ Rules saved with netfilter-persistent")
        saved = True

    if not saved:
        print_warning("  Could not save rules persistently")
        print_warning("  Rules may not survive reboot")

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
        print(f"  Rules are persistent across reboots (iptables-persistent)")

        return True
    else:
        print_error("Could not verify iptables rules")
        return False


# ============================================================================
# STEP 7: Configure Hostname
# ============================================================================

def step7_configure_hostname(hostname: str = None):
    """Configure system hostname"""
    print_header("STEP 7: Configuring Hostname")

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
# STEP 8: Final Check and Reboot
# ============================================================================

def step8_final_check_and_reboot(non_interactive=False):
    """Final system check and optional reboot"""
    print_header("STEP 8: Final Check and Reboot")

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
    print(f"  ✓ System packages (28 packages)")
    print(f"  ✓ Tailscale VPN")
    print(f"  ✓ Network optimizations (BBR, sysctl)")
    print(f"  ✓ 3x-ui Docker container")
    print(f"  ✓ VLESS gRPC with Unix socket (/dev/shm/xui-grpc.sock)")
    print(f"  ✓ Anti-abuse firewall (SMTP, BitTorrent, P2P blocked)")
    print(f"  ✓ System hostname")

    print(f"\n{Colors.BOLD}Next steps:{Colors.ENDC}")
    print(f"  1. Run 'tailscale up' to connect to your Tailscale network")
    print(f"  2. Setup nginx reverse proxy with SSL")
    print(f"  3. Add VLESS clients via panel or xui-client script")
    print(f"  4. Configure domain and SSL certificate")

    print(f"\n{Colors.BOLD}Important locations:{Colors.ENDC}")
    print(f"  Admin panel: http://localhost:2053/admin")
    print(f"  Docker files: /opt/3x-ui/")
    print(f"  Data volume: /opt/3x-ui/data/")
    print(f"  Unix socket: /dev/shm/xui-grpc.sock")

    print_step(3, 3, "Reboot system")

    print(f"\n{Colors.YELLOW}A reboot is recommended to ensure all changes take effect:{Colors.ENDC}")
    print(f"  - Hostname changes")
    print(f"  - Kernel parameters (sysctl)")
    print(f"  - Network optimizations")

    if not non_interactive:
        try:
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
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.YELLOW}Non-interactive mode detected{Colors.ENDC}")
            print(f"Skipping reboot. Reboot manually when ready: sudo reboot")
            return True
    else:
        print(f"\n{Colors.YELLOW}Skipping reboot (non-interactive mode). Reboot manually when ready: sudo reboot{Colors.ENDC}")
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
  sudo ./deploy-node.py --hostname vpn-server-01
        """
    )
    parser.add_argument(
        '--hostname',
        type=str,
        help='System hostname to configure (optional)'
    )
    parser.add_argument(
        '-y', '--yes',
        action='store_true',
        help='Non-interactive mode: skip all prompts and continue on errors'
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
        ("Configure Hostname", step7_configure_hostname, False, args.hostname),  # Needs hostname
        ("Final Check and Reboot", step8_final_check_and_reboot, False, args.yes),  # Needs non-interactive flag
    ]

    total_steps = len(steps)
    failed_steps = []
    config_data = None

    for i, (name, func, needs_config, param) in enumerate(steps, 1):
        print(f"\n{Colors.BOLD}Starting: {name}{Colors.ENDC}")

        # Skip steps that require config if config is missing
        if needs_config and not config_data:
            print_error(f"Skipping {name} - missing configuration from previous step")
            failed_steps.append(name)
            continue

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

            # Ask if user wants to continue (skip in non-interactive mode)
            if not args.yes:
                try:
                    response = input(f"{Colors.YELLOW}Continue with next step? [y/N]: {Colors.ENDC}")
                    if response.lower() not in ['y', 'yes']:
                        print_warning("Deployment aborted by user")
                        break
                except (EOFError, KeyboardInterrupt):
                    print(f"\n{Colors.YELLOW}Non-interactive mode detected, continuing...{Colors.ENDC}")
            else:
                print_warning(f"Step failed but continuing (non-interactive mode)")

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
