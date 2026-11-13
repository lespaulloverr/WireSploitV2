"""
Kali Linux Environment Detection and Integration Module

This module provides:
1. Detection of Kali Linux (native, WSL2, remote SSH)
2. Detection of installed Kali tools with versions
3. Updates tool diagnostics with real availability
4. Handles disconnected/missing executable scenarios gracefully
5. Lightweight design for 8GB RAM Windows 11
6. Abstracts connection for future remote Kali support
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .kali_categories import KaliCategory, ToolClassification


class KaliEnvironmentType(Enum):
    """Type of Kali environment detected."""
    NATIVE = "native"          # Running directly on Kali Linux
    WSL2 = "wsl2"              # Windows Subsystem for Linux 2
    SSH = "ssh"                # Remote Kali via SSH
    UNKNOWN = "unknown"        # Not detected


class ConnectionStatus(Enum):
    """Connection status for Kali environment."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    ERROR = "error"
    NOT_CONFIGURED = "not_configured"


@dataclass
class KaliToolInfo:
    """Information about a detected Kali tool."""
    name: str
    executable: str
    version: Optional[str] = None
    path: Optional[str] = None
    kali_category: Optional[KaliCategory] = None
    classification: Optional[ToolClassification] = None
    install_hint: str = ""
    available: bool = True
    last_checked: float = field(default_factory=time.time)
    error: Optional[str] = None


@dataclass
class KaliEnvironment:
    """Represents a detected Kali environment."""
    env_type: KaliEnvironmentType
    status: ConnectionStatus
    version: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    tools: Dict[str, KaliToolInfo] = field(default_factory=dict)
    last_scan: float = field(default_factory=time.time)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class KaliConnectionManager:
    """
    Manages connections to Kali environments.

    Supports:
    - Native Kali Linux detection
    - WSL2 detection and command execution
    - Remote SSH connections (future)
    """

    def __init__(self):
        self._environments: Dict[str, KaliEnvironment] = {}
        self._current_env_id: Optional[str] = None
        self._tool_version_cache: Dict[str, Tuple[str, float]] = {}  # tool -> (version, timestamp)
        self._cache_ttl = 3600  # 1 hour cache for version info

    def detect_environment(self) -> KaliEnvironment:
        """Detect the best available Kali environment."""
        # Try native Kali first
        native_env = self._detect_native_kali()
        if native_env.status == ConnectionStatus.CONNECTED:
            return native_env

        # Try WSL2
        wsl_env = self._detect_wsl2()
        if wsl_env.status == ConnectionStatus.CONNECTED:
            return wsl_env

        # Return the best we found (even if disconnected)
        if native_env.status != ConnectionStatus.NOT_CONFIGURED:
            return native_env
        return wsl_env

    def _detect_native_kali(self) -> KaliEnvironment:
        """Detect if running natively on Kali Linux."""
        env = KaliEnvironment(
            env_type=KaliEnvironmentType.NATIVE,
            status=ConnectionStatus.NOT_CONFIGURED
        )

        # Check if we're on Linux
        if platform.system() != "Linux":
            env.status = ConnectionStatus.DISCONNECTED
            env.error = "Not running on Linux"
            return env

        # Check for Kali-specific files
        kali_indicators = [
            "/etc/kali-release",
            "/etc/os-release",
        ]

        is_kali = False
        version = None

        for indicator in kali_indicators:
            if Path(indicator).exists():
                try:
                    content = Path(indicator).read_text()
                    if "kali" in content.lower():
                        is_kali = True
                        # Extract version
                        for line in content.splitlines():
                            if "version" in line.lower() or "version_id" in line.lower():
                                version = line.split("=")[-1].strip().strip('"')
                                break
                        break
                except Exception:
                    pass

        if not is_kali:
            # Check os-release for ID=kali
            try:
                content = Path("/etc/os-release").read_text()
                for line in content.splitlines():
                    if line.startswith("ID=") and "kali" in line.lower():
                        is_kali = True
                        break
            except Exception:
                pass

        if is_kali:
            env.status = ConnectionStatus.CONNECTED
            env.version = version or "unknown"
            env.hostname = platform.node()
            env.username = os.getenv("USER", "unknown")
        else:
            env.status = ConnectionStatus.DISCONNECTED
            env.error = "Not a Kali Linux system"

        return env

    def _detect_wsl2(self) -> KaliEnvironment:
        """Detect WSL2 with Kali Linux."""
        env = KaliEnvironment(
            env_type=KaliEnvironmentType.WSL2,
            status=ConnectionStatus.NOT_CONFIGURED
        )

        if platform.system() != "Windows":
            env.status = ConnectionStatus.DISCONNECTED
            env.error = "Not running on Windows"
            return env

        # Check if WSL is available
        try:
            result = subprocess.run(
                ["wsl", "--list", "--verbose"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                env.status = ConnectionStatus.DISCONNECTED
                env.error = "WSL not available or no distributions installed"
                return env

            # Parse output to find Kali
            lines = result.stdout.strip().splitlines()
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[0].replace("*", "").strip()
                    state = parts[1]
                    version = parts[2]

                    if "kali" in name.lower() and state == "Running" and version == "2":
                        env.status = ConnectionStatus.CONNECTED
                        env.hostname = name
                        env.version = f"WSL2 ({name})"
                        env.metadata["distro_name"] = name
                        env.metadata["wsl_version"] = version
                        break

            if env.status != ConnectionStatus.CONNECTED:
                env.status = ConnectionStatus.DISCONNECTED
                env.error = "Kali WSL2 distribution not found or not running"

        except subprocess.TimeoutExpired:
            env.status = ConnectionStatus.ERROR
            env.error = "WSL command timed out"
        except FileNotFoundError:
            env.status = ConnectionStatus.DISCONNECTED
            env.error = "WSL command not found"
        except Exception as e:
            env.status = ConnectionStatus.ERROR
            env.error = f"WSL detection failed: {e}"

        return env

    async def execute_in_kali(
        self,
        command: List[str],
        env_id: Optional[str] = None,
        timeout: int = 30,
        capture_output: bool = True
    ) -> Tuple[int, str, str]:
        """
        Execute a command in the Kali environment.

        Args:
            command: Command and arguments as a list
            env_id: Environment ID (uses current if not specified)
            timeout: Timeout in seconds
            capture_output: Whether to capture stdout/stderr

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        env = self._get_environment(env_id)
        if not env or env.status != ConnectionStatus.CONNECTED:
            return (1, "", f"Kali environment not available: {env.error if env else 'No environment'}")

        if env.env_type == KaliEnvironmentType.NATIVE:
            return await self._execute_native(command, timeout, capture_output)
        elif env.env_type == KaliEnvironmentType.WSL2:
            return await self._execute_wsl2(command, timeout, capture_output, env)
        else:
            return (1, "", f"Unsupported environment type: {env.env_type}")

    async def _execute_native(
        self,
        command: List[str],
        timeout: int,
        capture_output: bool
    ) -> Tuple[int, str, str]:
        """Execute command natively on Kali Linux."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE if capture_output else None,
                stderr=asyncio.subprocess.PIPE if capture_output else None,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                return (proc.returncode, stdout.decode('utf-8', errors='replace'), stderr.decode('utf-8', errors='replace'))
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return (1, "", f"Command timed out after {timeout}s")
        except Exception as e:
            return (1, "", str(e))

    async def _execute_wsl2(
        self,
        command: List[str],
        timeout: int,
        capture_output: bool,
        env: KaliEnvironment
    ) -> Tuple[int, str, str]:
        """Execute command in WSL2 Kali."""
        distro_name = env.metadata.get("distro_name", "kali-linux")
        wsl_cmd = ["wsl", "-d", distro_name, "--"] + command

        try:
            proc = await asyncio.create_subprocess_exec(
                *wsl_cmd,
                stdout=asyncio.subprocess.PIPE if capture_output else None,
                stderr=asyncio.subprocess.PIPE if capture_output else None,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                return (proc.returncode, stdout.decode('utf-8', errors='replace'), stderr.decode('utf-8', errors='replace'))
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return (1, "", f"WSL command timed out after {timeout}s")
        except Exception as e:
            return (1, "", str(e))

    def _get_environment(self, env_id: Optional[str] = None) -> Optional[KaliEnvironment]:
        """Get environment by ID or current environment."""
        if env_id:
            return self._environments.get(env_id)
        if self._current_env_id:
            return self._environments.get(self._current_env_id)
        # Auto-detect if no current
        env = self.detect_environment()
        self._current_env_id = f"{env.env_type.value}_{env.hostname or 'local'}"
        self._environments[self._current_env_id] = env
        return env

    def scan_tools(self, env_id: Optional[str] = None, tool_ids: Optional[List[str]] = None) -> Dict[str, KaliToolInfo]:
        """
        Scan for available Kali tools in the environment.

        Args:
            env_id: Environment ID to scan (uses current if not specified)
            tool_ids: Specific tool IDs to check (checks all known if not specified)

        Returns:
            Dictionary of tool_id -> KaliToolInfo
        """
        env = self._get_environment(env_id)
        if not env or env.status != ConnectionStatus.CONNECTED:
            return {}

        # Import the tool specs to know what to look for
        from .tooling import SPEC_BY_ID

        tools_to_check = tool_ids or list(SPEC_BY_ID.keys())
        results = {}

        for tool_id in tools_to_check:
            spec = SPEC_BY_ID.get(tool_id)
            if not spec or spec.kind != "cli":
                continue

            tool_info = self._check_tool_availability(spec, env)
            results[tool_id] = tool_info
            env.tools[tool_id] = tool_info

        env.last_scan = time.time()
        return results

    def _check_tool_availability(self, spec, env: KaliEnvironment) -> KaliToolInfo:
        """Check if a specific tool is available and get its version."""
        # Map spec IDs to executable names (same as in tooling.diagnose)
        executable_map = {
            "volatility3": "vol",
            "bulk_extractor": "bulk_extractor",
            "dnsgen": "dnsgen",
            "aircrack_ng": "aircrack-ng",
            "crackmapexec": "crackmapexec",
            "ldapdomaindump": "ldapdomaindump",
            "bloodhound": "SharpHound.exe",
            "faraday": "faraday-cli",
        }

        executable_name = executable_map.get(spec.id, spec.id)
        version = None
        path = None
        error = None
        available = False

        try:
            # Check if executable exists in PATH
            if env.env_type == KaliEnvironmentType.NATIVE:
                path = shutil.which(executable_name)
                if path:
                    available = True
                    version = self._get_tool_version(executable_name, [executable_name, spec.version_flag])
            elif env.env_type == KaliEnvironmentType.WSL2:
                # Use WSL to check
                distro_name = env.metadata.get("distro_name", "kali-linux")
                result = subprocess.run(
                    ["wsl", "-d", distro_name, "--", "which", executable_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    path = result.stdout.strip()
                    available = True
                    # Get version via WSL
                    version = self._get_tool_version_wsl(executable_name, spec.version_flag, distro_name)

        except Exception as e:
            error = str(e)

        return KaliToolInfo(
            name=spec.name,
            executable=executable_name,
            version=version,
            path=path,
            kali_category=spec.kali_category,
            classification=spec.classification,
            install_hint=spec.install_hint,
            available=available,
            error=error
        )

    def _get_tool_version(self, executable: str, version_cmd: List[str]) -> Optional[str]:
        """Get tool version from cache or by executing version command."""
        cache_key = executable
        now = time.time()

        # Check cache
        if cache_key in self._tool_version_cache:
            cached_version, cached_time = self._tool_version_cache[cache_key]
            if now - cached_time < self._cache_ttl:
                return cached_version

        # Execute version command
        try:
            result = subprocess.run(
                version_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version = result.stdout.strip().splitlines()[0] if result.stdout.strip() else "unknown"
                self._tool_version_cache[cache_key] = (version, now)
                return version
        except Exception:
            pass

        return None

    def _get_tool_version_wsl(self, executable: str, version_flag: str, distro_name: str) -> Optional[str]:
        """Get tool version via WSL."""
        cache_key = f"wsl:{distro_name}:{executable}"
        now = time.time()

        # Check cache
        if cache_key in self._tool_version_cache:
            cached_version, cached_time = self._tool_version_cache[cache_key]
            if now - cached_time < self._cache_ttl:
                return cached_version

        try:
            result = subprocess.run(
                ["wsl", "-d", distro_name, "--", executable, version_flag],
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode == 0:
                version = result.stdout.strip().splitlines()[0] if result.stdout.strip() else "unknown"
                self._tool_version_cache[cache_key] = (version, now)
                return version
        except Exception:
            pass

        return None

    def get_diagnostics_for_tools(self, env_id: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """
        Get diagnostic information for all tools in the environment.

        Returns dict suitable for merging with tooling.list_tools() output.
        """
        env = self._get_environment(env_id)
        if not env:
            return {}

        # Ensure tools are scanned
        if not env.tools or time.time() - env.last_scan > 300:  # Re-scan every 5 minutes
            self.scan_tools(env_id)

        diagnostics = {}
        for tool_id, tool_info in env.tools.items():
            if tool_info.available:
                diagnostics[tool_id] = {
                    "status": "ready",
                    "checks": [
                        {"detail": f"Found executable: {tool_info.path or tool_info.executable}"}
                    ],
                    "version": tool_info.version,
                    "kali_category": tool_info.kali_category.value if tool_info.kali_category else None,
                    "classification": tool_info.classification.value if tool_info.classification else None,
                    "install_hint": tool_info.install_hint,
                }
            else:
                diagnostics[tool_id] = {
                    "status": "missing",
                    "checks": [
                        {"detail": f"Executable '{tool_info.executable}' not found in PATH"}
                    ],
                    "install_hint": tool_info.install_hint,
                    "error": tool_info.error,
                }

        return diagnostics

    def get_environment_summary(self, env_id: Optional[str] = None) -> Dict[str, Any]:
        """Get a summary of the Kali environment for UI display."""
        env = self._get_environment(env_id)
        if not env:
            return {
                "type": "unknown",
                "status": "not_configured",
                "message": "No Kali environment detected"
            }

        ready_tools = sum(1 for t in env.tools.values() if t.available)
        missing_tools = sum(1 for t in env.tools.values() if not t.available)

        return {
            "type": env.env_type.value,
            "status": env.status.value,
            "version": env.version,
            "hostname": env.hostname,
            "username": env.username,
            "tools_total": len(env.tools),
            "tools_ready": ready_tools,
            "tools_missing": missing_tools,
            "last_scan": env.last_scan,
            "error": env.error,
        }


# Global instance for easy access
_kali_manager: Optional[KaliConnectionManager] = None


def get_kali_manager() -> KaliConnectionManager:
    """Get the global Kali connection manager instance."""
    global _kali_manager
    if _kali_manager is None:
        _kali_manager = KaliConnectionManager()
    return _kali_manager


async def initialize_kali_environment() -> KaliEnvironment:
    """Initialize and detect the Kali environment on startup."""
    manager = get_kali_manager()
    env = manager.detect_environment()
    if env.status == ConnectionStatus.CONNECTED:
        # Do initial tool scan in background
        asyncio.create_task(asyncio.to_thread(manager.scan_tools))
    return env


def get_kali_diagnostics() -> Dict[str, Any]:
    """Get diagnostics for all tools from the Kali environment."""
    manager = get_kali_manager()
    return manager.get_diagnostics_for_tools()


def get_kali_environment_summary() -> Dict[str, Any]:
    """Get a summary of the Kali environment for the diagnostics endpoint."""
    manager = get_kali_manager()
    return manager.get_environment_summary()


# Integration with tooling.py diagnostics
def enhance_tool_diagnostics(base_diagnostics: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhance base tool diagnostics with Kali environment information.

    This merges the Kali environment diagnostics with the base diagnostics
    from tooling.diagnose(), preferring Kali environment info for CLI tools.
    """
    kali_diagnostics = get_kali_diagnostics()

    enhanced = {}
    for tool_id, base_diag in base_diagnostics.items():
        if tool_id in kali_diagnostics:
            # Merge: Kali diagnostics take precedence for CLI tools
            kali_diag = kali_diagnostics[tool_id]
            enhanced[tool_id] = {**base_diag, **kali_diag}
        else:
            enhanced[tool_id] = base_diag

    return enhanced