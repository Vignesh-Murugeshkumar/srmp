# TraceVault Windows Endpoint Collector

Lightweight Windows endpoint digital forensics collector that identifies the machine, discovers available forensic artifact sources, acquires read-only forensic evidence with SHA-256 integrity hashing, and streams artifacts to the TraceVault backend.

## Commands

```powershell
# 1. Inspect endpoint identity
.\.venv\Scripts\python.exe -m tracevault_collector identify

# 2. Discover artifact availability on this machine
.\.venv\Scripts\python.exe -m tracevault_collector discover

# 3. Run an offline Quick Scan into a bundle directory
.\.venv\Scripts\python.exe -m tracevault_collector scan --type quick --hours 24 --out .\bundle_out

# 4. Enroll with the TraceVault backend
.\.venv\Scripts\python.exe -m tracevault_collector register --server http://127.0.0.1:8000 --enrollment-key dev-enrollment-key

# 5. Run the pull-model agent loop (poll queued scans, collect, upload)
.\.venv\Scripts\python.exe -m tracevault_collector agent --server http://127.0.0.1:8000
```

## Security & Forensic Integrity Guarantees

- **Strictly Read-Only Acquisition**: Registry keys are opened with `KEY_READ | KEY_WOW64_64KEY`; Browser SQLite databases are copied to temporary snapshots and opened with `?mode=ro`; Event logs are queried via `EvtQuery`.
- **Credential Exclusion**: Never accesses or transmits browser `Login Data`, `Cookies`, `Web Data`, `logins.json`, `key4.db`, LSA secrets, or SAM hashes.
- **Honest Privileges Reporting**: When executed without Administrator elevation, privileged artifacts (`Security.evtx`, `C:\Windows\Prefetch`, `Amcache.hve`, `$UsnJrnl:$J`, `$MFT`) are reported as `permission_denied` rather than silently omitted or fabricated.
