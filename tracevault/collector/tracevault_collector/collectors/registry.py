"""Windows Registry forensic collector (CONTRACT §4 & Spec §5.6).

Strictly read-only (KEY_READ | KEY_WOW64_64KEY). Never modifies registry keys.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, Iterator

from .. import __version__
from ..utils import filetime_to_iso, rot13, safe_artifact_filename, utc_now_iso, write_ndjson_records

try:
    import winreg
except ImportError:  # pragma: no cover
    winreg = None  # type: ignore

REG_TYPE_NAMES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}


def decode_userassist_entry(value_name: str, raw_data: bytes) -> dict[str, Any]:
    """Decode a ROT13 UserAssist value name and its binary payload (Windows 7+ 72-byte or XP 16-byte)."""
    decoded_name = rot13(value_name)
    result: dict[str, Any] = {
        "name": decoded_name,
        "run_count": None,
        "focus_count": None,
        "focus_time_ms": None,
        "last_executed": None,
    }
    if not isinstance(raw_data, (bytes, bytearray)):
        return result
    if len(raw_data) >= 72:
        # Win7 / Win10 / Win11 72-byte format:
        # offset 4: uint32 run_count
        # offset 8: uint32 focus_count
        # offset 12: uint32 focus_time_ms
        # offset 60: uint64 last_executed FILETIME
        run_count, focus_count, focus_time_ms = struct.unpack_from("<III", raw_data, 4)
        (ft,) = struct.unpack_from("<Q", raw_data, 60)
        result["run_count"] = int(run_count)
        result["focus_count"] = int(focus_count)
        result["focus_time_ms"] = int(focus_time_ms)
        result["last_executed"] = filetime_to_iso(ft)
    elif len(raw_data) == 16:
        # Legacy 16-byte format
        _, run_count, ft = struct.unpack("<IIQ", raw_data)
        result["run_count"] = max(0, int(run_count) - 5)
        result["last_executed"] = filetime_to_iso(ft)
    return result


def _format_reg_value(val: Any, reg_type: int) -> Any:
    if isinstance(val, bytes):
        return val[:256].hex()
    if isinstance(val, (list, tuple)):
        return [str(x) for x in val]
    return val


def _query_key_last_write(key_handle: Any) -> str | None:
    try:
        _, _, ft = winreg.QueryInfoKey(key_handle)
        return filetime_to_iso(ft)
    except Exception:
        return None


def _enum_values(key_handle: Any) -> list[tuple[str, Any, int]]:
    out: list[tuple[str, Any, int]] = []
    idx = 0
    while True:
        try:
            vname, vdata, vtype = winreg.EnumValue(key_handle, idx)
            out.append((vname, vdata, vtype))
            idx += 1
        except OSError:
            break
    return out


def _enum_subkeys(key_handle: Any) -> list[str]:
    out: list[str] = []
    idx = 0
    while True:
        try:
            out.append(winreg.EnumKey(key_handle, idx))
            idx += 1
        except OSError:
            break
    return out


def _iter_persistence_records() -> Iterator[dict[str, Any]]:
    if winreg is None:
        return
    targets = [
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "run"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "runonce"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "run"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "runonce"),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "run"),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "runonce"),
    ]
    for hive_name, root, subkey, cat in targets:
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                lw = _query_key_last_write(k)
                for vname, vdata, vtype in _enum_values(k):
                    yield {
                        "record_id": f"{hive_name}\\{subkey}:{vname or '(Default)'}",
                        "source": "registry",
                        "category": cat,
                        "hive": hive_name,
                        "key_path": f"{hive_name}\\{subkey}",
                        "value_name": vname or "(Default)",
                        "value_type": REG_TYPE_NAMES.get(vtype, str(vtype)),
                        "value_data": _format_reg_value(vdata, vtype),
                        "last_write": lw,
                        "timestamp_precision": "100ns",
                        "user_sid": None,
                        "decoded": {"command": str(vdata), "persistence_type": cat},
                    }
        except OSError:
            continue


def _iter_userassist_records(max_records: int = 500) -> Iterator[dict[str, Any]]:
    if winreg is None:
        return
    ua_root = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    emitted = 0
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ua_root, 0, winreg.KEY_READ) as k:
            guids = _enum_subkeys(k)
        for guid in guids:
            count_path = f"{ua_root}\\{guid}\\Count"
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_path, 0, winreg.KEY_READ) as ck:
                    lw = _query_key_last_write(ck)
                    for vname, vdata, vtype in _enum_values(ck):
                        if not isinstance(vdata, (bytes, bytearray)):
                            continue
                        decoded = decode_userassist_entry(vname, bytes(vdata))
                        if decoded["name"].startswith("UEME_CTLSESSION"):
                            continue
                        yield {
                            "record_id": f"HKCU\\{count_path}:{decoded['name']}",
                            "source": "registry",
                            "category": "userassist",
                            "hive": "HKCU",
                            "key_path": f"HKCU\\{count_path}",
                            "value_name": vname,
                            "value_type": REG_TYPE_NAMES.get(vtype, "REG_BINARY"),
                            "value_data": bytes(vdata).hex(),
                            "last_write": lw,
                            "timestamp_precision": "100ns",
                            "user_sid": None,
                            "decoded": decoded,
                        }
                        emitted += 1
                        if emitted >= max_records:
                            return
            except OSError:
                continue
    except OSError:
        return


def _iter_usbstor_records() -> Iterator[dict[str, Any]]:
    if winreg is None:
        return
    usb_root = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usb_root, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            dev_classes = _enum_subkeys(k)
        for dev_cls in dev_classes:
            cls_path = f"{usb_root}\\{dev_cls}"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cls_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as ck:
                    serials = _enum_subkeys(ck)
                for serial in serials:
                    inst_path = f"{cls_path}\\{serial}"
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, inst_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as ik:
                            lw = _query_key_last_write(ik)
                            vals = {vn: vd for vn, vd, _ in _enum_values(ik)}
                            parts = dev_cls.split("&")
                            vendor = next((p[4:] for p in parts if p.startswith("Ven_")), None)
                            product = next((p[5:] for p in parts if p.startswith("Prod_")), None)
                            revision = next((p[4:] for p in parts if p.startswith("Rev_")), None)
                            friendly = vals.get("FriendlyName") or vals.get("DeviceDesc") or dev_cls
                            yield {
                                "record_id": f"HKLM\\{inst_path}",
                                "source": "registry",
                                "category": "usb",
                                "hive": "HKLM",
                                "key_path": f"HKLM\\{inst_path}",
                                "value_name": "FriendlyName",
                                "value_type": "REG_SZ",
                                "value_data": str(friendly),
                                "last_write": lw,
                                "timestamp_precision": "100ns",
                                "user_sid": None,
                                "decoded": {
                                    "device_class": dev_cls,
                                    "vendor": vendor,
                                    "product": product,
                                    "revision": revision,
                                    "serial": serial,
                                    "friendly_name": str(friendly),
                                },
                            }
                    except OSError:
                        continue
            except OSError:
                continue
    except OSError:
        return


def _iter_installed_software_records(max_records: int = 400) -> Iterator[dict[str, Any]]:
    if winreg is None:
        return
    roots = [
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    emitted = 0
    for hive_name, root, base_path in roots:
        try:
            with winreg.OpenKey(root, base_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                subkeys = _enum_subkeys(k)
            for sk in subkeys:
                sk_path = f"{base_path}\\{sk}"
                try:
                    with winreg.OpenKey(root, sk_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as sub_k:
                        lw = _query_key_last_write(sub_k)
                        vals = {vn: vd for vn, vd, _ in _enum_values(sub_k)}
                        disp = vals.get("DisplayName")
                        if not disp:
                            continue
                        yield {
                            "record_id": f"{hive_name}\\{sk_path}",
                            "source": "registry",
                            "category": "installed_software",
                            "hive": hive_name,
                            "key_path": f"{hive_name}\\{sk_path}",
                            "value_name": "DisplayName",
                            "value_type": "REG_SZ",
                            "value_data": str(disp),
                            "last_write": lw,
                            "timestamp_precision": "100ns",
                            "user_sid": None,
                            "decoded": {
                                "display_name": str(disp),
                                "publisher": str(vals.get("Publisher")) if vals.get("Publisher") else None,
                                "version": str(vals.get("DisplayVersion")) if vals.get("DisplayVersion") else None,
                                "install_date": str(vals.get("InstallDate")) if vals.get("InstallDate") else None,
                                "install_location": str(vals.get("InstallLocation")) if vals.get("InstallLocation") else None,
                            },
                        }
                        emitted += 1
                        if emitted >= max_records:
                            return
                except OSError:
                    continue
        except OSError:
            continue


def _iter_services_records(max_records: int = 400) -> Iterator[dict[str, Any]]:
    if winreg is None:
        return
    svc_base = r"SYSTEM\CurrentControlSet\Services"
    emitted = 0
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, svc_base, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            subkeys = _enum_subkeys(k)
        for svc_name in subkeys:
            sk_path = f"{svc_base}\\{svc_name}"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sk_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as sk:
                    lw = _query_key_last_write(sk)
                    vals = {vn: vd for vn, vd, _ in _enum_values(sk)}
                    image_path = vals.get("ImagePath")
                    if not image_path:
                        continue
                    yield {
                        "record_id": f"HKLM\\{sk_path}",
                        "source": "registry",
                        "category": "services",
                        "hive": "HKLM",
                        "key_path": f"HKLM\\{sk_path}",
                        "value_name": "ImagePath",
                        "value_type": "REG_EXPAND_SZ",
                        "value_data": str(image_path),
                        "last_write": lw,
                        "timestamp_precision": "100ns",
                        "user_sid": None,
                        "decoded": {
                            "service_name": svc_name,
                            "image_path": str(image_path),
                            "start_type": int(vals["Start"]) if isinstance(vals.get("Start"), int) else None,
                            "service_type": int(vals["Type"]) if isinstance(vals.get("Type"), int) else None,
                            "display_name": str(vals.get("DisplayName")) if vals.get("DisplayName") else svc_name,
                            "object_name": str(vals.get("ObjectName")) if vals.get("ObjectName") else None,
                        },
                    }
                    emitted += 1
                    if emitted >= max_records:
                        return
            except OSError:
                continue
    except OSError:
        return


def _iter_profile_and_shell_records() -> Iterator[dict[str, Any]]:
    if winreg is None:
        return
    prof_base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, prof_base, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            sids = _enum_subkeys(k)
        for sid in sids:
            sk_path = f"{prof_base}\\{sid}"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sk_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as sk:
                    lw = _query_key_last_write(sk)
                    vals = {vn: vd for vn, vd, _ in _enum_values(sk)}
                    prof_img = vals.get("ProfileImagePath")
                    yield {
                        "record_id": f"HKLM\\{sk_path}",
                        "source": "registry",
                        "category": "profile",
                        "hive": "HKLM",
                        "key_path": f"HKLM\\{sk_path}",
                        "value_name": "ProfileImagePath",
                        "value_type": "REG_EXPAND_SZ",
                        "value_data": str(prof_img) if prof_img else sid,
                        "last_write": lw,
                        "timestamp_precision": "100ns",
                        "user_sid": sid,
                        "decoded": {
                            "sid": sid,
                            "profile_path": str(prof_img) if prof_img else None,
                        },
                    }
            except OSError:
                continue
    except OSError:
        pass

    winlogon_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, winlogon_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as wk:
            lw = _query_key_last_write(wk)
            vals = {vn: vd for vn, vd, _ in _enum_values(wk)}
            for field in ("Shell", "Userinit"):
                if field in vals:
                    yield {
                        "record_id": f"HKLM\\{winlogon_path}:{field}",
                        "source": "registry",
                        "category": "shell",
                        "hive": "HKLM",
                        "key_path": f"HKLM\\{winlogon_path}",
                        "value_name": field,
                        "value_type": "REG_SZ",
                        "value_data": str(vals[field]),
                        "last_write": lw,
                        "timestamp_precision": "100ns",
                        "user_sid": None,
                        "decoded": {"winlogon_field": field, "value": str(vals[field])},
                    }
    except OSError:
        pass


def collect_registry(out_dir: Path, scan_type: str = "quick") -> list[dict[str, Any]]:
    """Collect Windows Registry forensic artifacts across persistence, UserAssist, USB, software, services, profiles."""
    records_dir = out_dir / "records"
    records_dir.mkdir(parents=True, exist_ok=True)

    categories = [
        (
            "registry:Persistence",
            "Registry Run / RunOnce Persistence Keys",
            r"HKLM & HKCU \Software\Microsoft\Windows\CurrentVersion\Run*",
            _iter_persistence_records,
        ),
        (
            "registry:UserAssist",
            "UserAssist Execution Tracking",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
            lambda: _iter_userassist_records(300 if scan_type == "quick" else 1500),
        ),
        (
            "registry:USBSTOR",
            "USB Storage Device History",
            r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR",
            _iter_usbstor_records,
        ),
        (
            "registry:InstalledSoftware",
            "Installed Software Inventory (Uninstall)",
            r"HKLM & HKCU \Software\Microsoft\Windows\CurrentVersion\Uninstall",
            lambda: _iter_installed_software_records(250 if scan_type == "quick" else 1000),
        ),
        (
            "registry:Services",
            "Windows Services Registry Configuration",
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            lambda: _iter_services_records(250 if scan_type == "quick" else 1000),
        ),
        (
            "registry:Profiles",
            "User Profile & Shell Execution Keys",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList & Winlogon",
            _iter_profile_and_shell_records,
        ),
    ]

    results: list[dict[str, Any]] = []
    for artifact_key, name, loc, gen_fn in categories:
        safe_stem = safe_artifact_filename(artifact_key)
        ndjson_path = records_dir / f"{safe_stem}.ndjson"
        status = "collected"
        error_msg = None
        record_count = 0
        records_sha256 = None
        sz = 0
        try:
            record_count, records_sha256, sz = write_ndjson_records(ndjson_path, gen_fn())
        except Exception as exc:
            status = "error"
            error_msg = str(exc)[:200]
            if ndjson_path.exists():
                ndjson_path.unlink(missing_ok=True)

        meta = {
            "artifact_key": artifact_key,
            "source": "registry",
            "name": name,
            "original_path": loc,
            "status": status,
            "acquisition_method": "Live read-only winreg API (KEY_READ | KEY_WOW64_64KEY)",
            "sha256": None,
            "records_sha256": records_sha256,
            "size_bytes": sz,
            "last_modified": None,
            "collected_at": utc_now_iso(),
            "collector_version": __version__,
            "record_count": record_count,
            "parser": "winreg",
            "side_effects": ["Read-only registry handle inspection; no keys or values modified"],
            "error": error_msg,
            "time_window": None,
        }
        results.append(
            {
                "meta": meta,
                "records_path": str(ndjson_path) if (status == "collected" and ndjson_path.is_file()) else None,
                "original_path": None,
            }
        )
    return results
