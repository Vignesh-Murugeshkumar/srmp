"""Endpoint identification for Windows endpoints (CONTRACT §2)."""

from __future__ import annotations

import ctypes
import getpass
import os
import platform
import socket
import uuid
from typing import Any

from . import __version__
from .utils import utc_now_iso

try:
    import winreg
except ImportError:  # pragma: no cover
    winreg = None  # type: ignore


def is_process_elevated() -> bool:
    """Return True if the current process runs with Administrator privileges."""
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _read_machine_guid() -> str:
    if winreg is not None:
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as k:
                val, _ = winreg.QueryValueEx(k, "MachineGuid")
                if val:
                    return str(val).strip()
        except OSError:
            pass
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, socket.getfqdn() or socket.gethostname()))


def _read_windows_product_info() -> tuple[str, str, str]:
    os_name = f"Windows {platform.release()}"
    os_version = platform.version()
    os_build = platform.version().split(".")[-1] if "." in platform.version() else platform.version()
    if winreg is not None:
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as k:
                product = None
                try:
                    product, _ = winreg.QueryValueEx(k, "ProductName")
                except OSError:
                    pass
                try:
                    build, _ = winreg.QueryValueEx(k, "CurrentBuildNumber")
                    os_build = str(build)
                except OSError:
                    pass
                try:
                    maj, _ = winreg.QueryValueEx(k, "CurrentMajorVersionNumber")
                    minv, _ = winreg.QueryValueEx(k, "CurrentMinorVersionNumber")
                    os_version = f"{maj}.{minv}"
                except OSError:
                    pass
                if product:
                    # Windows 11 reports "Windows 10" in ProductName when build >= 22000
                    p_str = str(product)
                    try:
                        if int(os_build) >= 22000 and "Windows 10" in p_str:
                            p_str = p_str.replace("Windows 10", "Windows 11")
                    except ValueError:
                        pass
                    os_name = p_str
        except OSError:
            pass
    return os_name, os_version, os_build


def _collect_storage() -> list[dict[str, Any]]:
    drives: list[dict[str, Any]] = []
    if os.name != "nt":
        return drives
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if not (bitmask & (1 << i)):
            continue
        drive = f"{chr(65 + i)}:\\"
        dtype = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive))
        # 3 = DRIVE_FIXED, 2 = DRIVE_REMOVABLE
        if dtype not in (2, 3):
            continue
        free_bytes = ctypes.c_ulonglong(0)
        total_bytes = ctypes.c_ulonglong(0)
        avail_bytes = ctypes.c_ulonglong(0)
        ok = ctypes.windll.kernel32.GetDiskFreeSpaceExW(
            ctypes.c_wchar_p(drive),
            ctypes.byref(avail_bytes),
            ctypes.byref(total_bytes),
            ctypes.byref(free_bytes),
        )
        fs_buf = ctypes.create_unicode_buffer(64)
        ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(drive),
            None,
            0,
            None,
            None,
            None,
            fs_buf,
            len(fs_buf),
        )
        if ok:
            drives.append(
                {
                    "drive": drive,
                    "filesystem": fs_buf.value or "NTFS",
                    "total_bytes": int(total_bytes.value),
                    "free_bytes": int(free_bytes.value),
                }
            )
    return drives


def identify_endpoint() -> dict[str, Any]:
    """Identify the local Windows endpoint without exposing credentials or tokens."""
    os_name, os_version, os_build = _read_windows_product_info()
    domain = os.environ.get("USERDOMAIN")
    user = getpass.getuser()
    collection_user = f"{domain}\\{user}" if domain else user
    return {
        "machine_id": _read_machine_guid(),
        "hostname": socket.gethostname(),
        "os_name": os_name,
        "os_version": os_version,
        "os_build": os_build,
        "architecture": platform.machine() or "AMD64",
        "collection_user": collection_user,
        "is_elevated": is_process_elevated(),
        "agent_version": __version__,
        "storage": _collect_storage(),
        "collected_at": utc_now_iso(),
    }
