# TraceVault — Intelligent Windows Endpoint Digital Forensics & Evidence Reconstruction Platform

TraceVault is an automated Windows digital forensics workstation that identifies authorized Windows endpoints, discovers available forensic artifact sources, acquires read-only forensic evidence with SHA-256 verification and chain-of-custody tracking, normalizes events, deterministically correlates entities across artifact sources, evaluates rule-based MITRE ATT&CK detections, and reconstructs incidents through interactive graph and chronological visualizations.

## Repository Structure

```text
tracevault/
├── docs/
│   └── CONTRACT.md                 # Shared v1 binding API & schema contract
├── collector/                      # Windows Endpoint Collector (Python + pywin32)
│   ├── tracevault_collector/
│   │   ├── identity.py             # MachineGuid, OS build, privileges, NTFS drives
│   │   ├── discovery.py            # Pre-collection artifact availability checks
│   │   ├── agent.py                # Pull-model agent client & offline bundle runner
│   │   └── collectors/             # EVTX, Registry, Prefetch, Amcache, Browser, Filesystem
│   ├── tests/                      # Collector unit & live endpoint tests
│   └── build.ps1                   # Standalone PyInstaller packaging script
├── backend/                        # FastAPI + SQLAlchemy 2.0 + Alembic + ReportLab
│   ├── app/
│   │   ├── models/                 # All 20 forensic database tables
│   │   ├── api/routes.py           # REST & WebSocket endpoints
│   │   └── services/               # Storage, Ingestion, Normalization, Correlation, Detection, Graph, Reporting, Demo
│   ├── alembic/                    # Database migrations
│   └── tests/                      # Backend unit & API integration tests
├── frontend/                       # React 18 + TypeScript + Vite + Tailwind + Cytoscape + D3
│   └── src/
│       ├── api/                    # Typed API client & auth state
│       ├── screens/                # 5 Forensic Investigation Environments
│       ├── graph/                  # Cytoscape relationship/process-tree/cluster mapper
│       └── theme/                  # Graphite forensic workstation design system
└── docker-compose.yml              # PostgreSQL + Redis + Backend + Celery Worker + Nginx Frontend
```
