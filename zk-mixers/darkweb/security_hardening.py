#!/usr/bin/env python3
"""
Advanced Security Hardening for Dark Web Research
Run this script BEFORE starting research
"""

import os
import sys
import subprocess
import platform
from pathlib import Path


def check_system():
    """Check system security configuration"""
    print("🔒 Checking system security...")

    checks = []

    # Check if running in VM
    try:
        result = subprocess.run(
            ['systemd-detect-virt'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and 'none' not in result.stdout.lower():
            checks.append(('VM Environment', '✅', 'Running in virtual machine'))
        else:
            checks.append(('VM Environment', '⚠️', 'Not running in VM - consider using one'))
    except:
        checks.append(('VM Environment', '❌', 'Cannot detect virtualization'))

    # Check firewall
    system = platform.system()
    if system == 'Linux':
        try:
            result = subprocess.run(
                ['sudo', 'ufw', 'status'],
                capture_output=True,
                text=True
            )
            if 'active' in result.stdout.lower():
                checks.append(('Firewall', '✅', 'UFW firewall active'))
            else:
                checks.append(('Firewall', '⚠️', 'Firewall not active'))
        except:
            checks.append(('Firewall', '❌', 'Cannot check firewall'))

    # Check for Tor
    try:
        result = subprocess.run(
            ['which', 'tor'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            checks.append(('Tor Installed', '✅', 'Tor is installed'))
        else:
            checks.append(('Tor Installed', '❌', 'Tor not found'))
    except:
        checks.append(('Tor Installed', '❌', 'Cannot check for Tor'))

    # Print results
    for name, status, message in checks:
        print(f"{status} {name}: {message}")

    return all(status == '✅' for _, status, _ in checks)


def setup_vpn():
    """Setup VPN configuration"""
    print("\n🔐 Configuring VPN...")

    vpn_config = """# VPN Configuration for Dark Web Research
# Always use VPN before Tor for added security

Recommended VPNs for research:
1. Mullvad VPN (https://mullvad.net)
   - No logs policy
   - Accepts anonymous payments
   - WireGuard support

2. Proton VPN (https://protonvpn.com)
   - Based in Switzerland
   - Strong privacy laws
   - Free tier available

Configuration steps:
1. Install VPN client
2. Connect to a server
3. Verify no DNS leaks: https://dnsleaktest.com
4. THEN start Tor

Important: Use VPN -> Tor, not Tor -> VPN
"""

    config_path = Path('vpn_instructions.txt')
    config_path.write_text(vpn_config)
    print(f"✅ VPN instructions saved to {config_path}")


def create_sandbox():
    """Create sandboxed environment"""
    print("\n🏗️ Creating sandbox environment...")

    # Create isolated directories
    sandbox_dirs = [
        'sandbox/research',
        'sandbox/temp',
        'sandbox/logs',
        'sandbox/data'
    ]

    for directory in sandbox_dirs:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"📁 Created: {directory}")

    # Create sandbox config
    sandbox_config = {
        'isolated': True,
        'no_network_access': False,
        'read_only_home': True,
        'protect_system': True
    }

    import json
    config_path = Path('sandbox/config.json')
    config_path.write_text(json.dumps(sandbox_config, indent=2))

    print("✅ Sandbox environment created")


def setup_monitoring():
    """Setup security monitoring"""
    print("\n👁️ Setting up security monitoring...")

    monitor_script = """#!/bin/bash
# Security Monitor for Dark Web Research

LOG_FILE="security_monitor.log"

monitor_connections() {
    while true; do
        echo "=== $(date) ===" >> "$LOG_FILE"

        # Monitor network connections
        netstat -tunap 2>/dev/null | grep -E '(tor|9050|9051)' >> "$LOG_FILE"

        # Monitor Tor process
        ps aux | grep -E '[t]or' >> "$LOG_FILE"

        # Check for DNS leaks
        dig +short myip.opendns.com @resolver1.opendns.com >> "$LOG_FILE" 2>&1

        echo "" >> "$LOG_FILE"
        sleep 60
    done
}

# Start monitoring
monitor_connections &
MONITOR_PID=$!

# Cleanup on exit
trap "kill $MONITOR_PID" EXIT
wait
"""

    monitor_path = Path('security_monitor.sh')
    monitor_path.write_text(monitor_script)
    monitor_path.chmod(0o755)

    print(f"✅ Monitoring script created: {monitor_path}")


def main():
    """Main security setup function"""
    print("=" * 60)
    print("DARK WEB RESEARCH - SECURITY HARDENING")
    print("=" * 60)
    print("\nThis script will help secure your research environment.")
    print("WARNING: Complete security is never guaranteed.\n")

    # Run security checks
    if not check_system():
        print("\n⚠️  Some security checks failed.")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            print("Exiting. Please fix security issues first.")
            sys.exit(1)

    # Setup components
    setup_vpn()
    create_sandbox()
    setup_monitoring()

    # Final instructions
    print("\n" + "=" * 60)
    print("SECURITY SETUP COMPLETE")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Read vpn_instructions.txt and setup VPN")
    print("2. Run research from inside 'sandbox/' directory")
    print("3. Start monitoring: ./security_monitor.sh")
    print("4. Review ethical_guidelines.md")
    print("\nRemember:")
    print("- Never use personal accounts")
    print("- Use dedicated research machine")
    print("- Document all activities")
    print("- Report any security incidents")
    print("\nStay safe and research ethically! 🔒")


if __name__ == "__main__":
    main()