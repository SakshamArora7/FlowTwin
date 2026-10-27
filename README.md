# FlowTwin

A local Computer Networks and machine learning project for **authorized network traffic analysis**. “Twin” refers to the two directions of a network conversation: source to destination and the reply. Import a PCAP, inspect packet headers and bidirectional flows, classify those flows with a trained Random Forest, review alerts, replay packet/flow events through WebSockets, and export CSV/PDF reports. Sample mode is clearly separated from imported traffic.

## Packet Inspector V2

Open **Packet Inspector** for a sortable/filterable packet list, expandable protocol fields, linked hex/ASCII highlighting, and bounded TCP following. Live capture and imported PCAPs share the inspector. New packets retain bounded raw bytes locally; historical live packets remain metadata-only. See [inspector usage, filters, retention, and limits](docs/packet-inspector.md) and [official Wireshark reference research](docs/wireshark-reference.md).

## Four development phases

| Phase | Delivered |
| --- | --- |
| 1 — Foundation and dashboard | React/Vite, Tailwind, Framer Motion, Recharts, Lucide; FastAPI, SQLAlchemy, SQLite; eight routes, metrics, responsive dark UI, deterministic labeled sample mode |
| 2 — Packet analysis | Scapy PCAP/PCAPNG import; IPv4/IPv6 TCP/UDP/ICMP headers, packet records, bidirectional flow grouping, measured statistics, search/filter/detail views, bounded processing |
| 3 — AI engine | CIC-IDS2017 download script, versioned seven-feature training/inference schema, Random Forest, train/test evaluation, saved Joblib model, six supported categories, decision-path feature explanations |
| 4 — Monitoring and reports | Accelerated PCAP packet/flow replay over WebSockets, persisted alerts with New/Investigating/Resolved states, analytics, CSV/PDF export, integrated tests and walkthrough |

**Capture sources:** Genuine live interface capture, PCAP import, and saved-PCAP replay are supported. Live capture uses Scapy AsyncSniffer and requires Npcap/capture permissions on Windows. Select an authorized interface and use Start/Stop in Live Monitoring. The app never sends packets or executes packet payloads. See [Windows live monitoring setup, bounds, and testing](docs/live-monitoring.md).

## Windows setup (PowerShell)

Prerequisites: Python 3.11+ (verified with 3.13.14), Node.js 24, npm, internet access for first installation and dataset download. Clone the repository and run from its root:

```powershell
git clone https://github.com/SakshamArora7/FlowTwin.git
Set-Location FlowTwin
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
Set-Location frontend
npm.cmd ci
Set-Location ..
```

The following commands download five converted CIC-IDS2017 CSV tables from a [public Parquet mirror](https://huggingface.co/datasets/bvsam/cic-ids-2017), then train and evaluate the model. Source, size, and SHA-256 hashes are saved under `datasets/raw/manifest.json`. The upstream dataset is published by [UNB's Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html). Downloads total about 170 MB; additional disk space is needed for training.

```powershell
.\.venv\Scripts\python.exe datasets\fetch_cicids2017.py
.\.venv\Scripts\python.exe -m ml.train --data datasets\raw --output ml\artifacts --max-rows-per-class 6000
```

Training writes the model and measured metrics under `ml/artifacts/`; check `/api/model` to determine whether they are installed in your workspace. That directory is ignored by Git because model and source-data licensing/provenance should be handled separately when sharing the project. On a fresh checkout, run the commands above before expecting AI predictions. Until then, PCAP analysis still works and imported flows are marked **unanalyzed**. You can classify an existing capture with “Run trained model on capture” in Network Traffic, or select a completed session under **AI Threat Detection → Analyze saved traffic → Analyze capture**. New live flows and PCAP imports are classified automatically when the model is available. Readiness checks the actual model artifact, not only its metrics file.

Start the backend in one PowerShell terminal from the FlowTwin folder:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Start the frontend in another PowerShell terminal from the FlowTwin folder:

```powershell
Set-Location frontend
npm.cmd run dev
```

Open [FlowTwin](http://127.0.0.1:5174), [API health](http://127.0.0.1:8000/api/health), or [interactive API docs](http://127.0.0.1:8000/docs). Port **5174** is configured because another local application was already using 5173. Stop either server with Ctrl+C.

## Reviewer walkthrough

1. Explore the dashboard in **Sample data mode**. Every sample label and export carries a sample-data warning; these are UI fixtures, not model predictions.
2. In Settings, switch sample mode off and save.
3. Open Network Traffic and import a PCAP. For a short parser demo, use the included [synthetic sample capture](datasets/sample_capture.pcap). It has nine generated packets and **no ground-truth attack label**. For substantive network findings, import traffic collected with permission from a real network.
4. Inspect the packet table, filter the flow list, and open a flow to see measured statistics, the model result, confidence, and model-derived decision-path contributions. The synthetic PCAP may receive any model label; its contents do not certify the prediction.
5. Open AI Threat Detection and Analytics to view actual saved evaluation metrics and predictions from imported traffic.
6. Open Live Monitoring / Saved-PCAP replay, select the capture, and start **PCAP replay**. For genuine traffic, use the separate Live interface capture tab with Npcap installed and an explicitly selected adapter. Packet headers and analyzed flows stream over WebSockets at an accelerated pace; this is replay, not live interface capture.
7. Open Security Alerts and move a generated alert through New, Investigating, and Resolved. An alert appears only when a model result is non-benign.
8. Open Reports and export CSV or PDF. Sample exports are visibly marked; real exports report imported PCAP data.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests -q
Set-Location frontend
npm.cmd test
npm.cmd run build
```

The backend tests use isolated in-memory SQLite and synthetic PCAPs. They verify parsing, bidirectional counts, timeouts, upload validation, real/sample isolation, inference schema, replay events, alert status transitions, and CSV/PDF output. Frontend tests verify settings, flow filtering, API errors, saved-capture analysis, and automatic replay reconnection. Capture reanalysis runs in a worker thread and commits batches of 100 flows so dashboard reads and WebSockets remain responsive. Completed batches remain saved if analysis is interrupted; rerun the same capture safely to finish or refresh its predictions. Large sessions may take several minutes (the UI allows up to ten minutes). Additional API contracts are available at `/docs` while the backend runs.

## Model and trust limits

The installed model was trained on **50,117** selected CIC-IDS2017 flow rows and evaluated on **12,324** distinct later rows from the same source files. Measured weighted precision **94.84%**, recall **94.86%**, F1 **94.84%**, accuracy **94.86%**. Supported labels are Benign, Botnet, Brute force, DDoS, DoS, and Port scan. See [full evaluation and confusion matrix](docs/phases-2-to-4.md).

The train/test split removes identical feature vectors but does **not** hold out an entire capture day, network, or scenario. Class capping changes prevalence. The training CSVs were produced by CICFlowMeter; this app uses a Scapy parser with the same selected feature names, order, units, first-seen direction, and 120-second timeout. Full numerical equivalence across the two extractors has **not** been established against matched raw PCAPs. Treat PCAP predictions as investigative signals, not confirmed attacks or field-accuracy claims. The dashboard never claims that a model score proves malicious activity.

## Project map

```text
backend/app/     FastAPI, database, PCAP/flow analysis, model inference, replay, alerts, reports
backend/tests/   Isolated API and full pipeline tests
frontend/src/    React dashboard, charts, traffic browser, monitoring, detection and reports
ml/              Shared feature schema and CIC-IDS2017 training script
ml/artifacts/    Local generated model and evaluation results (ignored)
datasets/        Download script, provenance, and clearly synthetic sample PCAP
datasets/raw/    Downloaded CIC-IDS2017 Parquet files (ignored)
docs/            Architecture, implementation notes, screenshots, and viva answers
uploads/         Imported PCAPs retained locally (ignored)
```

Watch the [expanded English demo video](docs/flowtwin-demo-english.mp4) or the [English-screen video with Hindi narration](docs/flowtwin-demo-english-screen-hindi-voice.mp4). Both use real application screenshots. Read the [English script](docs/english-demo-script.md) or [Hindi narration](docs/hindi-demo-script.md). For a live teacher demonstration, use the [presentation guide](docs/presentation-guide.md). Also see [architecture](docs/architecture.md), [Phases 2–4, measured evaluation and screenshots](docs/phases-2-to-4.md), and [viva questions](docs/viva.md). Historical [Phase 1 notes](docs/phase-1.md) remain for provenance.

## Troubleshooting

- **No real data:** turn sample mode off, then import a PCAP. Sample and real records are isolated.
- **No model result:** check `/api/model`. Run the training commands and use “Run trained model on capture” for captures imported earlier.
- **Upload rejected:** PCAP/PCAPNG magic is validated; files over 25 MB, over 50,000 packets, or over 5,000 flows are rejected before a partial database commit.
- **No replay updates:** keep the frontend on port 5174 and backend on 8000. The Vite proxy forwards `/api/ws/monitor`; select a previously imported capture. The replay page reconnects automatically after a dropped socket and restores server progress; packet events missed while disconnected are not replayed.
- **Windows capture warning:** Scapy can read PCAP files without Npcap. Npcap/capture permissions are required for the Live interface capture tab; offline PCAP analysis remains available without them.
- **Installation connection reset:** retry `npm.cmd ci --maxsockets=1 --fetch-retries=5` or repeat pip installation on a stable connection. Do not disable certificate verification.
- **Local storage:** `backend/flowtwin.db`, uploaded PCAPs, and model artifacts are local, unencrypted development data. Use only authorized captures and do not publish the API to an untrusted network.
