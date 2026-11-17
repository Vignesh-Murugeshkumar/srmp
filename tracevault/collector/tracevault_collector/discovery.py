"""Artifact discovery before collection (CONTRACT §3.4 & Spec §5.2)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .identity import is_process_elevated
from .utils import filetime_to_iso, stat_info

try:
    import winreg
except ImportError:  # pragma: no cover
    winreg = None  # type: ignore

EVTX_CHANNELS = [
    ("evtx:Security", "Security event log", "Security", r"C:\Windows\System32\winevt\Logs\Security.evtx", True),
    ("evtx:System", "System event log", "System", r"C:\Windows\System32\winevt\Logs\System.evtx", False),
    ("evtx:Application", "Application event log", "Application", r"C:\Windows\System32\winevt\Logs\Application.evtx", False),
    (
        "evtx:PowerShell",
        "PowerShell Operational log",
        "Microsoft-Windows-PowerShell/Operational",
        r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
        False,
    ),
    (
        "evtx:Defender",
        "Windows Defender Operational log",
        "Microsoft-Windows-Windows Defender/Operational",
        r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx",
        False,
    ),
    (
        "evtx:TaskScheduler",
        "Task Scheduler Operational log",
        "Microsoft-Windows-TaskScheduler/Operational",
        r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx",
        False,
    ),
    (
        "evtx:Sysmon",
        "Sysmon Operational log",
        "Microsoft-Windows-Sysmon/Operational",
        r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
        False,
    ),
]


def _check_file_access(path: str, requires_elevation: bool = False) -> tuple[str, int | None, str | None, str | None]:
    """Return (availability, size_bytes, last_modified, access_note)."""
    p = Path(path)
    size_bytes, last_mod = stat_info(p)
    try:
        exists = p.exists()
    except PermissionError:
        return "permission_denied", size_bytes, last_mod, "Access denied (requires Administrator elevation)"
    except OSError as exc:
        return "permission_denied", size_bytes, last_mod, str(exc)

    if not exists:
        if requires_elevation and not is_process_elevated():
            return "permission_denied", None, None, "Requires Administrator elevation"
        return "not_found", None, None, "Artifact file not present on this endpoint"
    try:
        with p.open("rb") as f:
            f.read(16)
        return "available", size_bytes, last_mod, None
    except PermissionError:
        return "permission_denied", size_bytes, last_mod, "Access denied (requires elevation or system privileges)"
    except OSError as e:
        if getattr(e, "winerror", None) == 32:  # ERROR_SHARING_VIOLATION
            return "partially_accessible", size_bytes, last_mod, "Locked by OS; requires safe snapshot/copy or parser"
        return "permission_denied", size_bytes, last_mod, str(e)


def _check_evtx_channel(channel: str, file_path: str, requires_elevation: bool) -> dict[str, Any]:
    size_bytes, last_mod = stat_info(file_path)
    try:
        import win32evtlog  # type: ignore

        h = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, "*")
        _ = win32evtlog.EvtNext(h, 1, 100, 0)
        return {
            "availability": "available",
            "last_modified": last_mod,
            "size_bytes": size_bytes,
            "access_note": "Live EvtQuery API accessible",
        }
    except Exception as exc:
        msg = str(exc)
        if "5" in msg or "Access is denied" in msg or (requires_elevation and not is_process_elevated()):
            return {
                "availability": "permission_denied",
                "last_modified": last_mod,
                "size_bytes": size_bytes,
                "access_note": "Requires Administrator elevation or Event Log Readers membership",
            }
        if "15007" in msg or "could not be found" in msg.lower() or not Path(file_path).exists():
            return {
                "availability": "not_found",
                "last_modified": None,
                "size_bytes": None,
                "access_note": "Channel not installed/enabled on endpoint",
            }
        return {
            "availability": "partially_accessible",
            "last_modified": last_mod,
            "size_bytes": size_bytes,
            "access_note": msg[:160],
        }


def discover_artifacts() -> list[dict[str, Any]]:
    """Inspect local endpoint for all supported forensic artifact sources."""
    items: list[dict[str, Any]] = []
    elevated = is_process_elevated()

    # 1. EVTX channels
    for key, name, channel, fpath, req_elev in EVTX_CHANNELS:
        info = _check_evtx_channel(channel, fpath, req_elev)
        items.append(
            {
                "source": "evtx",
                "artifact_key": key,
                "name": name,
                "location": fpath,
                "availability": info["availability"],
                "last_modified": info["last_modified"],
                "size_bytes": info["size_bytes"],
                "access_note": info["access_note"],
            }
        )

    # 2. Registry sources
    reg_targets = [
        ("registry:Persistence", "Registry Run / RunOnce Persistence Keys", r"HKLM & HKCU \Software\Microsoft\Windows\CurrentVersion\Run*"),
        ("registry:UserAssist", "UserAssist Execution Tracking", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"),
        ("registry:USBSTOR", "USB Storage Device History", r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"),
        ("registry:InstalledSoftware", "Installed Software Inventory (Uninstall)", r"HKLM & HKCU \Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("registry:Services", "Windows Services Registry Configuration", r"HKLM\SYSTEM\CurrentControlSet\Services"),
        ("registry:Profiles", "User Profile & Shell Execution Keys", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList & Winlogon"),
    ]
    for key, name, loc in reg_targets:
        last_mod = None
        avail = "available"
        note = "Read-only winreg API access"
        if winreg is None:
            avail = "unsupported"
            note = "winreg module unavailable"
        else:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ) as k:
                    _, _, ft = winreg.QueryInfoKey(k)
                    last_mod = filetime_to_iso(ft)
            except OSError:
                pass
        items.append(
            {
                "source": "registry",
                "artifact_key": key,
                "name": name,
                "location": loc,
                "availability": avail,
                "last_modified": last_mod,
                "size_bytes": None,
                "access_note": note,
            }
        )

    # 3. Prefetch
    pf_dir = Path(r"C:\Windows\Prefetch")
    pf_avail = "permission_denied"
    pf_note = "Requires Administrator elevation to list C:\\Windows\\Prefetch"
    pf_size, pf_mod = stat_info(pf_dir)
    if not elevated:
        pf_avail = "permission_denied"
    elif pf_dir.exists():
        try:
            _ = list(os.scandir(pf_dir))
            pf_files = list(pf_dir.glob("*.pf"))
            pf_avail = "available"
            pf_size = sum((f.stat().st_size for f in pf_files if f.is_file()), 0)
            pf_note = f"{len(pf_files)} .pf files readable"
        except PermissionError:
            pf_avail = "permission_denied"
    else:
        pf_avail = "not_found"
        pf_note = "C:\\Windows\\Prefetch directory not found"
    items.append(
        {
            "source": "prefetch",
            "artifact_key": "prefetch:WindowsPrefetch",
            "name": "Windows Prefetch (*.pf)",
            "location": str(pf_dir),
            "availability": pf_avail,
            "last_modified": pf_mod,
            "size_bytes": pf_size,
            "access_note": pf_note,
        }
    )

    # 4. Amcache
    amcache_path = r"C:\Windows\appcompat\Programs\Amcache.hve"
    am_avail, am_size, am_mod, am_note = _check_file_access(amcache_path, requires_elevation=True)
    if not elevated and am_avail in ("partially_accessible", "available"):
        # Amcache.hve is locked by the kernel and requires elevation/AmcacheParser
        am_avail = "permission_denied"
        am_note = "Locked system hive; requires Administrator elevation"
    items.append(
        {
            "source": "amcache",
            "artifact_key": "amcache:AmcacheHve",
            "name": "Amcache Application Inventory (Amcache.hve)",
            "location": amcache_path,
            "availability": am_avail,
            "last_modified": am_mod,
            "size_bytes": am_size,
            "access_note": am_note,
        }
    )

    # 5. Browsers (Chrome, Edge, Firefox)
    local_app = os.environ.get("LOCALAPPDATA", "")
    roaming_app = os.environ.get("APPDATA", "")
    browser_defs = [
        ("browser:Chrome", "Google Chrome History & Downloads", os.path.join(local_app, r"Google\Chrome\User Data")),
        ("browser:Edge", "Microsoft Edge History & Downloads", os.path.join(local_app, r"Microsoft\Edge\User Data")),
        ("browser:Firefox", "Mozilla Firefox Places & Downloads", os.path.join(roaming_app, r"Mozilla\Firefox\Profiles")),
    ]
    for key, name, root in browser_defs:
        p = Path(root)
        if not root or not p.exists():
            items.append(
                {
                    "source": "browser",
                    "artifact_key": key,
                    "name": name,
                    "location": root or "N/A",
                    "availability": "not_found",
                    "last_modified": None,
                    "size_bytes": None,
                    "access_note": "Browser profile directory not present for current user",
                }
            )
            continue
        db_files = list(p.glob("*/History")) + list(p.glob("History")) + list(p.glob("*/places.sqlite"))
        total_sz = sum((f.stat().st_size for f in db_files if f.is_file()), 0)
        latest_mod = None
        for f in db_files:
            _, m = stat_info(f)
            if m and (latest_mod is None or m > latest_mod):
                latest_mod = m
        items.append(
            {
                "source": "browser",
                "artifact_key": key,
                "name": name,
                "location": str(p),
                "availability": "available" if db_files else "not_found",
                "last_modified": latest_mod,
                "size_bytes": total_sz if db_files else None,
                "access_note": f"{len(db_files)} SQLite profile database(s) discovered (snapshot copy read-only)" if db_files else "No History/places.sqlite found",
            }
        )

    # 6. Filesystem (Recycle Bin, User Downloads/Temp metadata, USN Journal, $MFT)
    rb_path = Path(r"C:\$Recycle.Bin")
    rb_size, rb_mod = stat_info(rb_path)
    items.append(
        {
            "source": "filesystem",
            "artifact_key": "filesystem:RecycleBin",
            "name": "Recycle Bin Deletion Metadata ($I records)",
            "location": str(rb_path),
            "availability": "available" if rb_path.exists() else "not_found",
            "last_modified": rb_mod,
            "size_bytes": rb_size,
            "access_note": "User SID Recycle Bin $I metadata accessible",
        }
    )

    user_profile = os.environ.get("USERPROFILE", "")
    dl_path = os.path.join(user_profile, "Downloads") if user_profile else r"C:\Users"
    _, dl_mod = stat_info(dl_path)
    items.append(
        {
            "source": "filesystem",
            "artifact_key": "filesystem:UserFiles",
            "name": "User Downloads, Desktop & Temp File Metadata",
            "location": dl_path,
            "availability": "available" if Path(dl_path).exists() else "not_found",
            "last_modified": dl_mod,
            "size_bytes": None,
            "access_note": "Read-only file stat + SHA-256 hashing (<50MB)",
        }
    )

    items.append(
        {
            "source": "filesystem",
            "artifact_key": "filesystem:USNJournal",
            "name": "NTFS Change Journal ($UsnJrnl:$J)",
            "location": r"\\.\C:\$Extend\$UsnJrnl:$J",
            "availability": "available" if elevated else "permission_denied",
            "last_modified": None,
            "size_bytes": None,
            "access_note": "Accessible via elevated fsutil usn readjournal" if elevated else "Requires Administrator elevation",
        }
    )

    items.append(
        {
            "source": "filesystem",
            "artifact_key": "filesystem:MFT",
            "name": "NTFS Master File Table ($MFT)",
            "location": r"\\.\C:\$MFT",
            "availability": "available" if elevated else "permission_denied",
            "last_modified": None,
            "size_bytes": None,
            "access_note": "Raw volume FILE record header inspection (elevated)" if elevated else "Requires Administrator elevation for raw volume read",
        }
    )

    return items
