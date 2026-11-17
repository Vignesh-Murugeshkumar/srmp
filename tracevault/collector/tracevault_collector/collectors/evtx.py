"""Windows Event Log (EVTX) collector and XML parser (CONTRACT §4 & Spec §5.5)."""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .. import __version__
from ..discovery import EVTX_CHANNELS
from ..utils import safe_artifact_filename, sha256_file, stat_info, utc_now_iso, write_ndjson_records

PRIORITY_SECURITY_EVENT_IDS = [
    4624,  # Successful logon
    4625,  # Failed logon
    4634,  # Logoff
    4648,  # Explicit credentials used
    4672,  # Special privileges assigned
    4688,  # Process creation
    4697,  # Service installation
    4698,  # Scheduled task created
    4720,  # User account created
    4728,  # Member added to global group
    4732,  # Member added to local group
    7045,  # Service installation (System)
    1102,  # Security audit log cleared
]

EVTX_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def parse_evtx_xml(xml_str: str, fallback_channel: str = "") -> dict[str, Any] | None:
    """Parse a rendered Windows Event XML string into the CONTRACT §4 evtx schema."""
    if not xml_str or not xml_str.strip():
        return None
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    def _find(parent: ET.Element | None, tag: str) -> ET.Element | None:
        if parent is None:
            return None
        el = parent.find(f"{EVTX_NS}{tag}")
        if el is None:
            el = parent.find(tag)
        return el

    sys_el = _find(root, "System")
    if sys_el is None:
        return None

    prov_el = _find(sys_el, "Provider")
    provider = (prov_el.attrib.get("Name") or prov_el.attrib.get("Guid") or "") if prov_el is not None else ""

    ev_id_el = _find(sys_el, "EventID")
    try:
        event_id = int(ev_id_el.text.strip()) if (ev_id_el is not None and ev_id_el.text) else 0
    except ValueError:
        event_id = 0

    rec_el = _find(sys_el, "EventRecordID")
    try:
        record_number = int(rec_el.text.strip()) if (rec_el is not None and rec_el.text) else 0
    except ValueError:
        record_number = 0

    lvl_el = _find(sys_el, "Level")
    try:
        level = int(lvl_el.text.strip()) if (lvl_el is not None and lvl_el.text) else None
    except ValueError:
        level = None

    tc_el = _find(sys_el, "TimeCreated")
    time_created = tc_el.attrib.get("SystemTime") if tc_el is not None else None
    if time_created and time_created.endswith("Z"):
        time_created = time_created[:-1] + "+00:00"

    chan_el = _find(sys_el, "Channel")
    channel = (chan_el.text.strip() if (chan_el is not None and chan_el.text) else "") or fallback_channel

    comp_el = _find(sys_el, "Computer")
    computer = comp_el.text.strip() if (comp_el is not None and comp_el.text) else None

    sec_el = _find(sys_el, "Security")
    user_sid = sec_el.attrib.get("UserID") if sec_el is not None else None

    exec_el = _find(sys_el, "Execution")
    process_id = None
    thread_id = None
    if exec_el is not None:
        try:
            if "ProcessID" in exec_el.attrib:
                process_id = int(exec_el.attrib["ProcessID"], 0)
        except ValueError:
            pass
        try:
            if "ThreadID" in exec_el.attrib:
                thread_id = int(exec_el.attrib["ThreadID"], 0)
        except ValueError:
            pass

    event_data: dict[str, Any] = {}
    ed_el = _find(root, "EventData")
    if ed_el is not None:
        idx = 0
        for child in list(ed_el):
            local_tag = child.tag.split("}")[-1]
            if local_tag == "Data":
                name = child.attrib.get("Name") or f"Data_{idx}"
                event_data[name] = (child.text or "").strip()
                idx += 1
            elif local_tag == "Binary" and child.text:
                event_data["Binary"] = child.text.strip()

    ud_el = _find(root, "UserData")
    if ud_el is not None and not event_data:
        for elem in ud_el.iter():
            if elem is ud_el:
                continue
            local_tag = elem.tag.split("}")[-1]
            if elem.text and elem.text.strip():
                event_data[local_tag] = elem.text.strip()

    return {
        "record_id": f"{channel}:{record_number}",
        "source": "evtx",
        "channel": channel,
        "provider": provider,
        "event_id": event_id,
        "record_number": record_number,
        "level": level,
        "time_created": time_created,
        "timestamp_precision": "100ns",
        "computer": computer,
        "user_sid": user_sid,
        "process_id": process_id,
        "thread_id": thread_id,
        "event_data": event_data,
        "xml": xml_str,
    }


def _build_xpath_query(channel: str, scan_type: str, start_dt: datetime | None) -> str:
    clauses: list[str] = []
    if start_dt is not None:
        iso_z = start_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        clauses.append(f"TimeCreated[@SystemTime>='{iso_z}']")
    if scan_type == "quick" and channel == "Security":
        id_or = " or ".join(f"EventID={eid}" for eid in PRIORITY_SECURITY_EVENT_IDS)
        clauses.append(f"({id_or})")
    if not clauses:
        return "*"
    return f"*[System[{' and '.join(clauses)}]]"


def _iter_channel_records(
    channel: str,
    xpath: str,
    max_records: int,
) -> Iterator[dict[str, Any]]:
    import win32evtlog  # type: ignore

    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
    handle = win32evtlog.EvtQuery(channel, flags, xpath)
    emitted = 0
    while emitted < max_records:
        batch_size = min(64, max_records - emitted)
        events = win32evtlog.EvtNext(handle, batch_size, 2000, 0)
        if not events:
            break
        for ev in events:
            try:
                xml_str = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                parsed = parse_evtx_xml(xml_str, fallback_channel=channel)
                if parsed is not None:
                    yield parsed
                    emitted += 1
                    if emitted >= max_records:
                        break
            except Exception:
                continue


def collect_evtx(
    out_dir: Path,
    scan_type: str = "quick",
    time_window_hours: int | None = 72,
    max_records_per_channel: int = 2500,
) -> list[dict[str, Any]]:
    """Collect Windows Event Logs across security-relevant channels."""
    now = datetime.now(timezone.utc)
    start_dt = (
        now - timedelta(hours=time_window_hours)
        if (scan_type == "quick" and time_window_hours)
        else (now - timedelta(hours=time_window_hours) if time_window_hours else None)
    )
    time_window_meta = {
        "start": start_dt.isoformat() if start_dt else None,
        "end": now.isoformat(),
    }

    results: list[dict[str, Any]] = []
    records_dir = out_dir / "records"
    originals_dir = out_dir / "originals"
    records_dir.mkdir(parents=True, exist_ok=True)
    originals_dir.mkdir(parents=True, exist_ok=True)

    for artifact_key, name, channel, file_path, _ in EVTX_CHANNELS:
        size_bytes, last_mod = stat_info(file_path)
        xpath = _build_xpath_query(channel, scan_type, start_dt)
        safe_stem = safe_artifact_filename(artifact_key)
        ndjson_path = records_dir / f"{safe_stem}.ndjson"
        original_copy_path: Path | None = None
        orig_sha256: str | None = None
        side_effects = ["Read-only EvtQuery live channel API query; source .evtx untouched"]
        status = "collected"
        error_msg: str | None = None
        record_count = 0
        records_sha256: str | None = None

        try:
            # First probe channel access before opening NDJSON file
            import win32evtlog  # type: ignore

            probe = win32evtlog.EvtQuery(
                channel,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath,
            )
            _ = probe
            record_count, records_sha256, _ = write_ndjson_records(
                ndjson_path,
                _iter_channel_records(channel, xpath, max_records_per_channel),
            )

            # In full scan, also attempt faithful export of the .evtx file
            if scan_type == "full":
                exp_target = originals_dir / f"{safe_stem}.evtx"
                try:
                    if hasattr(win32evtlog, "EvtExportLog"):
                        win32evtlog.EvtExportLog(
                            None,
                            channel,
                            xpath,
                            str(exp_target),
                            win32evtlog.EvtExportLogChannelPath,
                        )
                    else:
                        subprocess.run(
                            ["wevtutil.exe", "epl", channel, str(exp_target), "/ow:true"],
                            check=True,
                            capture_output=True,
                            timeout=30,
                        )
                    if exp_target.is_file():
                        original_copy_path = exp_target
                        orig_sha256 = sha256_file(exp_target)
                        size_bytes = exp_target.stat().st_size
                        side_effects.append("Exported faithful .evtx copy to collector staging directory")
                except Exception as exp_exc:
                    side_effects.append(f"Live records collected; raw .evtx export skipped ({str(exp_exc)[:80]})")

        except Exception as exc:
            msg = str(exc)
            if ndjson_path.exists():
                ndjson_path.unlink(missing_ok=True)
            if "5" in msg or "Access is denied" in msg:
                status = "permission_denied"
                error_msg = f"{channel}: Access is denied (requires Administrator elevation)"
            elif "15007" in msg or "could not be found" in msg.lower() or not Path(file_path).exists():
                status = "not_found"
                error_msg = f"{channel}: Event channel not present on this endpoint"
            else:
                status = "error"
                error_msg = f"{channel}: {msg[:200]}"

        meta = {
            "artifact_key": artifact_key,
            "source": "evtx",
            "name": name,
            "original_path": file_path,
            "status": status,
            "acquisition_method": "EvtQuery live channel query (pywin32)"
            + (" + EvtExportLog" if original_copy_path else ""),
            "sha256": orig_sha256,
            "records_sha256": records_sha256,
            "size_bytes": size_bytes,
            "last_modified": last_mod,
            "collected_at": utc_now_iso(),
            "collector_version": __version__,
            "record_count": record_count,
            "parser": "pywin32-evtquery",
            "side_effects": side_effects,
            "error": error_msg,
            "time_window": time_window_meta,
        }
        results.append(
            {
                "meta": meta,
                "records_path": str(ndjson_path) if (status == "collected" and ndjson_path.is_file()) else None,
                "original_path": str(original_copy_path) if original_copy_path else None,
            }
        )

    return results
