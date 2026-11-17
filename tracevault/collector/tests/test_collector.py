"""Unit tests for the TraceVault Windows Endpoint Collector."""

from __future__ import annotations

import json
import sqlite3
import struct
from pathlib import Path

import responses

from tracevault_collector.agent import CollectorClient
from tracevault_collector.collectors.browser import (
    extract_chromium_sqlite_records,
    extract_firefox_sqlite_records,
)
from tracevault_collector.collectors.evtx import parse_evtx_xml
from tracevault_collector.collectors.filesystem import parse_recycle_bin_i_bytes
from tracevault_collector.collectors.prefetch import parse_prefetch_filename
from tracevault_collector.collectors.registry import decode_userassist_entry
from tracevault_collector.discovery import discover_artifacts
from tracevault_collector.identity import identify_endpoint
from tracevault_collector.utils import (
    filetime_to_iso,
    prtime_to_iso,
    rot13,
    sha256_bytes,
    webkit_to_iso,
    write_ndjson_records,
)


def test_rot13_and_userassist_decoding() -> None:
    encoded = rot13(r"C:\Users\Admin\Downloads\updater.exe")
    assert encoded != r"C:\Users\Admin\Downloads\updater.exe"
    assert rot13(encoded) == r"C:\Users\Admin\Downloads\updater.exe"

    # Build a synthetic 72-byte Win10/11 UserAssist payload
    buf = bytearray(72)
    # run_count=7, focus_count=12, focus_time_ms=45000, ft=133761024000000000 (2024-11-15T00:00:00Z)
    struct.pack_into("<III", buf, 4, 7, 12, 45000)
    struct.pack_into("<Q", buf, 60, 133761024000000000)

    decoded = decode_userassist_entry(encoded, bytes(buf))
    assert decoded["name"] == r"C:\Users\Admin\Downloads\updater.exe"
    assert decoded["run_count"] == 7
    assert decoded["focus_count"] == 12
    assert decoded["focus_time_ms"] == 45000
    assert decoded["last_executed"] == "2024-11-15T00:00:00+00:00"


def test_recycle_bin_v2_and_v1_parsing() -> None:
    orig_path = r"C:\Users\Vignesh\Downloads\invoice_macro.docm"
    utf16_bytes = (orig_path + "\x00").encode("utf-16-le")
    char_count = len(orig_path) + 1
    ft = 133761024000000000  # 2024-11-15T00:00:00+00:00
    header_v2 = struct.pack("<QQQI", 2, 184320, ft, char_count) + utf16_bytes
    rec = parse_recycle_bin_i_bytes(header_v2, r"C:\$Recycle.Bin\S-1-5-21-1001\$I8F3A2B.docm")
    assert rec is not None
    assert rec["kind"] == "recycle_bin"
    assert rec["size"] == 184320
    assert rec["original_path"] == orig_path
    assert rec["deleted_time"] == "2024-11-15T00:00:00+00:00"
    assert rec["attributes"] == "RecycleBin_v2"


def test_timestamp_conversions() -> None:
    assert filetime_to_iso(133761024000000000) == "2024-11-15T00:00:00+00:00"
    assert webkit_to_iso(13376102400000000) == "2024-11-15T00:00:00+00:00"
    assert prtime_to_iso(1731715200000000) == "2024-11-16T00:00:00+00:00"
    assert filetime_to_iso(0) is None
    assert webkit_to_iso(-5) is None


def test_evtx_xml_parsing() -> None:
    sample_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
        <EventID>4688</EventID>
        <Version>2</Version>
        <Level>0</Level>
        <Opcode>0</Opcode>
        <TimeCreated SystemTime="2026-11-16T10:15:30.1234567Z"/>
        <EventRecordID>99412</EventRecordID>
        <Execution ProcessID="4" ThreadID="128"/>
        <Channel>Security</Channel>
        <Computer>WORKSTATION-01</Computer>
        <Security UserID="S-1-5-18"/>
      </System>
      <EventData>
        <Data Name="SubjectUserName">Vignesh</Data>
        <Data Name="NewProcessId">0x1a40</Data>
        <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
        <Data Name="CommandLine">powershell.exe -nop -w hidden -enc SQBFAFgA</Data>
        <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
      </EventData>
    </Event>"""
    parsed = parse_evtx_xml(sample_xml)
    assert parsed is not None
    assert parsed["record_id"] == "Security:99412"
    assert parsed["event_id"] == 4688
    assert parsed["channel"] == "Security"
    assert parsed["computer"] == "WORKSTATION-01"
    assert parsed["time_created"] == "2026-11-16T10:15:30.1234567+00:00"
    assert parsed["event_data"]["SubjectUserName"] == "Vignesh"
    assert parsed["event_data"]["NewProcessName"].endswith("powershell.exe")


def test_synthetic_browser_sqlite_extraction(tmp_path: Path) -> None:
    chrome_db = tmp_path / "History"
    conn = sqlite3.connect(chrome_db)
    cur = conn.cursor()
    cur.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)")
    cur.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)")
    cur.execute(
        """CREATE TABLE downloads (
            id INTEGER PRIMARY KEY, target_path TEXT, current_path TEXT,
            start_time INTEGER, end_time INTEGER, received_bytes INTEGER,
            total_bytes INTEGER, state INTEGER, danger_type INTEGER,
            referrer TEXT, tab_url TEXT, mime_type TEXT
        )"""
    )
    cur.execute("CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT)")
    cur.execute("INSERT INTO urls VALUES (1, 'https://files.example.org/payload.exe', 'Payload Portal', 3)")
    cur.execute("INSERT INTO visits VALUES (10, 1, 13376102400000000, 805306368)")
    cur.execute(
        "INSERT INTO downloads VALUES (5, 'C:\\Users\\Vignesh\\Downloads\\payload.exe', 'C:\\Users\\Vignesh\\Downloads\\payload.exe', 13376102410000000, 13376102420000000, 204800, 204800, 1, 1, 'https://files.example.org/', 'https://files.example.org/', 'application/x-msdownload')"
    )
    cur.execute("INSERT INTO downloads_url_chains VALUES (5, 0, 'https://cdn.example.org/payload.exe')")
    conn.commit()
    conn.close()

    rows = list(extract_chromium_sqlite_records(chrome_db, "chrome", "Default"))
    assert len(rows) == 2
    dl = next(r for r in rows if r["kind"] == "download")
    visit = next(r for r in rows if r["kind"] == "visit")
    assert dl["target_path"] == r"C:\Users\Vignesh\Downloads\payload.exe"
    assert dl["url"] == "https://cdn.example.org/payload.exe"
    assert dl["danger_type"] == "DANGEROUS_FILE"
    assert visit["url"] == "https://files.example.org/payload.exe"

    # Firefox places.sqlite
    ff_db = tmp_path / "places.sqlite"
    conn2 = sqlite3.connect(ff_db)
    c2 = conn2.cursor()
    c2.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)")
    c2.execute("CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER)")
    c2.execute("INSERT INTO moz_places VALUES (1, 'https://mozilla.org/security', 'Mozilla Security', 2)")
    c2.execute("INSERT INTO moz_historyvisits VALUES (99, 1, 1731715200000000, 1)")
    conn2.commit()
    conn2.close()

    ff_rows = list(extract_firefox_sqlite_records(ff_db, "default-release"))
    assert len(ff_rows) == 1
    assert ff_rows[0]["url"] == "https://mozilla.org/security"
    assert ff_rows[0]["visit_time"] == "2024-11-16T00:00:00+00:00"


def test_ndjson_writer_and_prefetch_filename(tmp_path: Path) -> None:
    exe, pf_hash = parse_prefetch_filename("POWERSHELL.EXE-A1B2C3D4.pf")
    assert exe == "POWERSHELL.EXE"
    assert pf_hash == "A1B2C3D4"

    ndjson_file = tmp_path / "records.ndjson"
    recs = [{"record_id": "1", "source": "evtx"}, {"record_id": "2", "source": "evtx"}]
    count, digest, sz = write_ndjson_records(ndjson_file, recs)
    assert count == 2
    assert sz == ndjson_file.stat().st_size
    assert digest == sha256_bytes(ndjson_file.read_bytes())


@responses.activate
def test_collector_client_protocol(tmp_path: Path) -> None:
    server = "http://127.0.0.1:8000"
    responses.add(
        responses.POST,
        f"{server}/api/endpoints/register",
        json={"endpoint_id": "ep-1", "agent_id": "ag-1", "agent_token": "tok-secret"},
        status=200,
    )
    responses.add(
        responses.POST,
        f"{server}/api/agent/heartbeat",
        json={"ok": True},
        status=200,
    )
    responses.add(
        responses.POST,
        f"{server}/api/agent/scans/scan-1/artifacts",
        json={"artifact_id": "art-1", "verified": True, "record_count": 1},
        status=200,
    )
    responses.add(
        responses.POST,
        f"{server}/api/agent/scans/scan-1/complete",
        json={"ok": True},
        status=200,
    )

    client = CollectorClient(server)
    reg = client.register_endpoint("dev-enrollment-key", identity={"hostname": "TEST-HOST", "machine_id": "m-1"})
    assert reg["agent_id"] == "ag-1"
    assert client.heartbeat(discovery=[]) == {"ok": True}

    ndjson = tmp_path / "sample.ndjson"
    ndjson.write_text(json.dumps({"record_id": "r1", "source": "registry"}) + "\n", encoding="utf-8")
    up = client.upload_artifact(
        "scan-1",
        meta={"artifact_key": "registry:Persistence", "source": "registry", "status": "collected", "record_count": 1},
        records_path=ndjson,
    )
    assert up["verified"] is True
    comp = client.complete_scan("scan-1", "completed", [], [])
    assert comp["ok"] is True


def test_live_identify_and_discover() -> None:
    ident = identify_endpoint()
    assert ident["hostname"]
    assert ident["machine_id"]
    assert isinstance(ident["is_elevated"], bool)
    disc = discover_artifacts()
    assert len(disc) >= 12
    assert any(d["source"] == "evtx" for d in disc)
    assert any(d["source"] == "registry" for d in disc)
