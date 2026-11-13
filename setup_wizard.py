#!/usr/bin/env python3
"""
WireSploit Setup Wizard

A guided setup wizard for configuring WireSploit v4.0.1.
Run this before first use to configure:
- API keys for web providers
- Kali Linux environment detection
- Database initialization
- Server configuration
"""

import os
import sys
import json
import subprocess
import shutil
from pathlib import Path
from typing import Optional, Dict, Any

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from config import get_config


class Colors:
    """ANSI color codes for console output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_header(text: str):
    """Print a formatted header."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text:^60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}\n")


def print_step(step: int, total: int, text: str):
    """Print a step indicator."""
    print(f"{Colors.CYAN}[Step {step}/{total}] {text}{Colors.ENDC}")


def print_success(text: str):
    """Print success message."""
    print(f"{Colors.GREEN}✓ {text}{Colors.ENDC}")


def print_warning(text: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.ENDC}")


def print_error(text: str):
    """Print error message."""
    print(f"{Colors.RED}✗ {text}{Colors.ENDC}")


def print_info(text: str):
    """Print info message."""
    print(f"{Colors.BLUE}ℹ {text}{Colors.ENDC}")


def prompt_yes_no(question: str, default: bool = True) -> bool:
    """Prompt user for yes/no answer."""
    suffix = " [Y/n]" if default else " [y/N]"
    while True:
        try:
            answer = input(f"{question}{suffix}: ").strip().lower()
            if not answer:
                return default
            if answer in ('y', 'yes'):
                return True
            if answer in ('n', 'no'):
                return False
            print("Please answer 'y' or 'n'")
        except KeyboardInterrupt:
            print("\nSetup cancelled.")
            sys.exit(1)


def prompt_input(question: str, default: str = "", required: bool = False) -> str:
    """Prompt user for text input."""
    suffix = f" [{default}]" if default else ""
    while True:
        try:
            answer = input(f"{question}{suffix}: ").strip()
            if not answer and default:
                return default
            if not answer and required:
                print("This field is required.")
                continue
            return answer
        except KeyboardInterrupt:
            print("\nSetup cancelled.")
            sys.exit(1)


def prompt_choice(question: str, choices: list, default: int = 0) -> int:
    """Prompt user to choose from a list."""
    print(f"\n{question}")
    for i, choice in enumerate(choices):
        marker = "→" if i == default else " "
        print(f"  {marker} {i+1}. {choice}")
    while True:
        try:
            answer = input(f"Enter choice [1-{len(choices)}] (default {default+1}): ").strip()
            if not answer:
                return default
            idx = int(answer) - 1
            if 0 <= idx < len(choices):
                return idx
            print(f"Please enter a number between 1 and {len(choices)}")
        except ValueError:
            print("Please enter a valid number")
        except KeyboardInterrupt:
            print("\nSetup cancelled.")
            sys.exit(1)


def check_python_version() -> bool:
    """Check if Python version is compatible."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 10):
        print_error(f"Python 3.10+ required, found {version.major}.{version.minor}")
        return False
    print_success(f"Python {version.major}.{version.minor}.{version.micro} OK")
    return True


def check_dependencies() -> bool:
    """Check if required dependencies are installed."""
    required = [
        'fastapi', 'uvicorn', 'pydantic', 'playwright',
        'reportlab', 'cryptography', 'requests', 'httpx'
    ]
    missing = []
    for pkg in required:
        try:
            __import__(pkg)
            print_success(f"  {pkg} OK")
        except ImportError:
            missing.append(pkg)
            print_error(f"  {pkg} MISSING")

    if missing:
        print_warning(f"Missing packages: {', '.join(missing)}")
        if prompt_yes_no("Install missing packages now?"):
            subprocess.run([sys.executable, "-m", "pip", "install"] + missing, check=True)
            print_success("Dependencies installed")
        else:
            return False
    return True


def setup_api_keys() -> Dict[str, str]:
    """Configure API keys for web providers."""
    print_header("API Keys Configuration")

    api_keys = {
        'URLSCAN_API_KEY': 'URLScan.io (https://urlscan.io/user/signup)',
        'SHODAN_API_KEY': 'Shodan (https://account.shodan.io/)',
        'VIRUSTOTAL_API_KEY': 'VirusTotal (https://www.virustotal.com/gui/sign-up)',
        'ABUSEIPDB_API_KEY': 'AbuseIPDB (https://www.abuseipdb.com/register.html)',
        'GREYNOISE_API_KEY': 'GreyNoise (https://viz.greynoise.io/signup)',
        'CENSYS_API_ID': 'Censys (https://censys.io/register)',
        'CENSYS_API_SECRET': 'Censys Secret',
    }

    configured = {}
    for key, description in api_keys.items():
        print(f"\n{Colors.BOLD}{key}{Colors.ENDC}")
        print(f"  {description}")
        current = os.environ.get(key, "")
        if current:
            print(f"  Current: {Colors.GREEN}***configured***{Colors.ENDC}")
            if prompt_yes_no("  Update this key?", default=False):
                value = prompt_input("  Enter new value", required=False)
                if value:
                    configured[key] = value
        else:
            print(f"  Current: {Colors.RED}not set{Colors.ENDC}")
            if prompt_yes_no("  Configure this key?", default=False):
                value = prompt_input("  Enter value", required=False)
                if value:
                    configured[key] = value

    return configured


def detect_kali_environment() -> Dict[str, Any]:
    """Detect and configure Kali Linux environment."""
    print_header("Kali Linux Environment Detection")

    result = {
        'type': 'none',
        'wsl_distro': None,
        'ssh_host': None,
        'ssh_user': None,
        'ssh_key': None,
    }

    # Check for WSL2 Kali
    if sys.platform == 'win32':
        try:
            wsl_result = subprocess.run(
                ['wsl', '--list', '--verbose'],
                capture_output=True, text=True, timeout=10
            )
            if wsl_result.returncode == 0:
                for line in wsl_result.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        name = parts[0].replace('*', '').strip()
                        state = parts[1]
                        version = parts[2]
                        if 'kali' in name.lower() and state == 'Running' and version == '2':
                            print_success(f"Found Kali WSL2: {name}")
                            if prompt_yes_no(f"Use WSL2 distro '{name}' for Kali tools?"):
                                result['type'] = 'wsl2'
                                result['wsl_distro'] = name
                                break
        except Exception:
            pass

    # Check for native Kali
    if sys.platform == 'linux':
        try:
            with open('/etc/os-release') as f:
                content = f.read().lower()
                if 'kali' in content:
                    print_success("Running on native Kali Linux")
                    if prompt_yes_no("Use native Kali environment?"):
                        result['type'] = 'native'
        except Exception:
            pass

    # SSH option
    if result['type'] == 'none':
        print_info("No local Kali environment detected")
        if prompt_yes_no("Configure remote Kali via SSH?"):
            host = prompt_input("SSH hostname or IP", required=True)
            user = prompt_input("SSH username", default="kali")
            key = prompt_input("SSH private key path (optional)", default="")
            result['type'] = 'ssh'
            result['ssh_host'] = host
            result['ssh_user'] = user
            result['ssh_key'] = key if key else None

    return result


def setup_database() -> bool:
    """Initialize the database."""
    print_header("Database Initialization")

    from engine import store
    try:
        store.init()
        print_success("Database initialized successfully")
        return True
    except Exception as e:
        print_error(f"Database initialization failed: {e}")
        return False


def setup_server_config() -> Dict[str, Any]:
    """Configure server settings."""
    print_header("Server Configuration")

    config = get_config()
    current_host = config.get('HOST', '127.0.0.1')
    current_port = config.get('PORT', 8000)

    print(f"Current host: {current_host}")
    print(f"Current port: {current_port}")

    if prompt_yes_no("Change server host/port?"):
        host = prompt_input("Host", default=current_host)
        port = prompt_input("Port", default=str(current_port))
        try:
            port = int(port)
        except ValueError:
            print_warning("Invalid port, using default")
            port = current_port
        return {'HOST': host, 'PORT': port}

    return {}


def write_env_file(api_keys: Dict[str, str], kali_config: Dict[str, Any], server_config: Dict[str, Any]):
    """Write configuration to .env file."""
    print_header("Writing Configuration")

    env_path = ROOT / '.env'
    lines = []

    # Read existing .env if present
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key = line.split('=', 1)[0]
                    # Don't overwrite keys we're managing
                    if key not in api_keys and key not in server_config:
                        lines.append(line)

    # Add API keys
    if api_keys:
        lines.append('\n# Web Provider API Keys')
        for key, value in api_keys.items():
            lines.append(f'{key}="{value}"')

    # Add Kali config
    if kali_config.get('type') != 'none':
        lines.append('\n# Kali Environment')
        lines.append(f'KALI_ENV_TYPE="{kali_config["type"]}"')
        if kali_config.get('wsl_distro'):
            lines.append(f'KALI_WSL_DISTRO="{kali_config["wsl_distro"]}"')
        if kali_config.get('ssh_host'):
            lines.append(f'KALI_SSH_HOST="{kali_config["ssh_host"]}"')
        if kali_config.get('ssh_user'):
            lines.append(f'KALI_SSH_USER="{kali_config["ssh_user"]}"')
        if kali_config.get('ssh_key'):
            lines.append(f'KALI_SSH_KEY="{kali_config["ssh_key"]}"')

    # Add server config
    if server_config:
        lines.append('\n# Server Configuration')
        for key, value in server_config.items():
            lines.append(f'{key}="{value}"')

    with open(env_path, 'w') as f:
        f.write('\n'.join(lines) + '\n')

    print_success(f"Configuration written to {env_path}")


def create_shortcuts():
    """Create desktop/start menu shortcuts (Windows)."""
    if sys.platform != 'win32':
        return

    print_header("Creating Shortcuts")

    if not prompt_yes_no("Create desktop shortcut?"):
        return

    try:
        import winshell
        from win32com.client import Dispatch

        desktop = winshell.desktop()
        shortcut_path = os.path.join(desktop, "WireSploit.lnk")
        exe_path = str(ROOT / 'dist' / 'WireSploit.exe')

        if not Path(exe_path).exists():
            print_warning("Executable not found at dist/WireSploit.exe")
            print_info("Run 'pyinstaller wiresploit.spec --clean' to build first")
            return

        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = exe_path
        shortcut.WorkingDirectory = str(ROOT)
        shortcut.IconLocation = exe_path
        shortcut.Description = "WireSploit v4.0.1 - OSINT Investigation Platform"
        shortcut.save()

        print_success(f"Desktop shortcut created: {shortcut_path}")
    except ImportError:
        print_warning("winshell/pywin32 not available, skipping shortcut creation")
        print_info("Install with: pip install winshell pywin32")
    except Exception as e:
        print_warning(f"Could not create shortcut: {e}")


def run_tests() -> bool:
    """Run basic tests to verify installation."""
    print_header("Running Verification Tests")

    if not prompt_yes_no("Run basic tests to verify installation?"):
        return True

    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pytest', 'tests/test_core.py', 'tests/test_api_contracts.py', '-v'],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            print_success("All tests passed!")
            return True
        else:
            print_warning("Some tests failed (this may be expected for optional features)")
            print(result.stdout[-2000:] if result.stdout else result.stderr[-2000:])
            return False
    except subprocess.TimeoutExpired:
        print_warning("Tests timed out")
        return False
    except Exception as e:
        print_warning(f"Could not run tests: {e}")
        return False


def main():
    """Main setup wizard entry point."""
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("  ============================================================")
    print("   WireSploit v4.0.1 Setup Wizard")
    print("  ============================================================")
    print(f"{Colors.ENDC}")
    print(f"\nThis wizard will help you configure WireSploit for first use.\n")

    if not prompt_yes_no("Continue with setup?"):
        print("Setup cancelled.")
        return

    # Step 1: Check Python version
    print_step(1, 7, "Checking Python version")
    if not check_python_version():
        sys.exit(1)

    # Step 2: Check dependencies
    print_step(2, 7, "Checking dependencies")
    check_dependencies()

    # Step 3: Configure API keys
    print_step(3, 7, "Configuring API keys")
    api_keys = setup_api_keys()

    # Step 4: Detect Kali environment
    print_step(4, 7, "Detecting Kali environment")
    kali_config = detect_kali_environment()

    # Step 5: Initialize database
    print_step(5, 7, "Initializing database")
    setup_database()

    # Step 6: Configure server
    print_step(6, 7, "Configuring server")
    server_config = setup_server_config()

    # Step 7: Write configuration
    print_step(7, 7, "Writing configuration")
    write_env_file(api_keys, kali_config, server_config)

    # Optional: Create shortcuts
    create_shortcuts()

    # Optional: Run tests
    run_tests()

    # Final summary
    print_header("Setup Complete!")
    print(f"{Colors.GREEN}{Colors.BOLD}WireSploit v4.0.1 is ready to use!{Colors.ENDC}\n")
    print("Next steps:")
    print(f"  1. Run the server: {Colors.CYAN}python main.py{Colors.ENDC} or {Colors.CYAN}./dist/WireSploit.exe{Colors.ENDC}")
    print(f"  2. Open browser: {Colors.CYAN}http://localhost:8000{Colors.ENDC} (or your configured port)")
    print(f"  3. Create an investigation and start exploring!\n")
    print(f"Documentation: {Colors.BLUE}README.md{Colors.ENDC}")
    print(f"Configuration: {Colors.BLUE}.env{Colors.ENDC}")


if __name__ == '__main__':
    main()