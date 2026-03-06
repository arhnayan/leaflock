import hashlib
import os
import platform
import subprocess
import sys


def _get_linux_machine_id() -> str:
    paths = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
    combined = b""
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    combined += f.read().strip()
            except (IOError, OSError):
                pass
    return combined.decode("utf-8") if combined else ""


def _get_macos_machine_id() -> str:
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.split("\n"):
            if "IOPlatformUUID" in line:
                return line.split('"')[-2]
    except (subprocess.SubprocessError, OSError):
        pass
    return ""


def _get_windows_machine_id() -> str:
    try:
        result = subprocess.run(
            ["wmic", "csproduct", "get", "UUID"],
            capture_output=True,
            text=True,
            timeout=10
        )
        lines = result.stdout.strip().split("\n")
        if len(lines) > 1:
            return lines[1].strip()
    except (subprocess.SubprocessError, OSError):
        pass
    return ""


def get_machine_id() -> str:
    system = platform.system()
    
    if system == "Linux":
        raw_id = _get_linux_machine_id()
    elif system == "Darwin":
        raw_id = _get_macos_machine_id()
    elif system == "Windows":
        raw_id = _get_windows_machine_id()
    else:
        raw_id = ""
    
    if not raw_id:
        fallback = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        raw_id = fallback
    
    return hashlib.sha256(raw_id.encode("utf-8")).hexdigest()
