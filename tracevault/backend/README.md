# TraceVault Backend API & Forensic Reconstruction Engine

FastAPI backend providing 20 PostgreSQL/SQLite forensic tables, content-addressed SHA-256 evidence storage, chain-of-custody tracking, event normalization, deterministic cross-artifact correlation, 10 MITRE ATT&CK-mapped detection rules, Time Travel graph reconstruction, and 13-section PDF/JSON forensic reporting.

## Running Locally

```powershell
cd d:\PROJECTS\cn\tracevault\backend
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000
```
