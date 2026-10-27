# Phases 2–4: implementation and verification

This document describes the final integrated build. [Phase 1 notes](phase-1.md) retain the original foundation record. All results here were measured from actual code or the stated training dataset. A model score is a signal for investigation, not confirmation of malicious traffic.

## Phase 2 — Network packet analysis

Implemented: bounded PCAP and PCAPNG uploads; Scapy parsing of IPv4/IPv6 TCP, UDP and ICMP; per-packet timestamp, address, port, protocol, size and flags; bidirectional flow aggregation; measured byte counts, duration, packet lengths, inter-arrival and TCP flag statistics; searchable flow and packet tables; capture list and flow detail view. Analytics includes a packet-size histogram computed from imported packet records. Flow direction is set by the first observed packet. The flow timeout is 120 seconds, with TCP FIN/RST closure handling. Packet payloads are not stored.

Validation: synthetic PCAP tests cover packet counts, forward/backward direction, flag counts, feature duration, timeouts, invalid upload rejection and demo/real isolation. The included `datasets/sample_capture.pcap` is clearly synthetic, generated for the reviewer walkthrough. It has no ground-truth attack label. The parser accepts a file only if its extension and header magic match recognized capture formats, and enforces 25 MB / 50,000 packet / 5,000 flow limits. Invalid captures do not commit partial database rows.

Files added: `backend/app/traffic.py`, capture/packet/flow models in `backend/app/models.py`, upload and browsing routes in `backend/app/advanced.py`, `datasets/generate_sample_pcap.py`, `datasets/sample_capture.pcap`, and the Network Traffic UI in `frontend/src/pages.jsx`. Tests: `backend/tests/test_pipeline.py`.

Limitation: direct interface capture is optional and has not been enabled. The working fallback is a PCAP import followed by accelerated packet/flow replay. Windows users can parse PCAP files without Npcap; actual interface sniffing would require Npcap and suitable permissions on a network they are authorized to monitor.

## Phase 3 — AI detection engine

The project downloads five CIC-IDS2017 machine-learning flow tables converted to Parquet by the [bvsam public mirror](https://huggingface.co/datasets/bvsam/cic-ids-2017), whose source is the [UNB/CIC dataset](https://www.unb.ca/cic/datasets/ids-2017.html). The download script saves exact source URLs, sizes and SHA-256 digests in an ignored local manifest. It does not relabel the source rows. The selected files include DDoS, PortScan, Bot, FTP/SSH Patator and DoS examples as well as benign traffic. Labels outside these categories are excluded. Brute-force-related rows are grouped under Brute force; specific DoS subtypes are grouped under DoS.

`ml/schema.py` defines seven ordered CIC-IDS2017 feature names and units shared with inference: microsecond duration, forward/backward packet counts, and FIN/SYN/RST/ACK flag counts. Training converts columns to numeric, replaces non-finite values with missing, drops rows with too few valid fields, removes duplicate labeled feature vectors, and uses a **median imputer fit only on training rows**. A Random Forest with 120 trees, `min_samples_leaf=3`, balanced subtree weights and seed 42 is saved with the imputer in `model.joblib` along with ordered features and schema version. The API checks this contract before inference. Confidence comes from `predict_proba`; local explanation contributions come from tree decision paths.

### Measured evaluation, 25 October 2026

Training rows: **50,117**. Later held-out distinct rows: **12,324**. Class sizes were capped at 6,000 training rows and up to 1,500 test rows per source-file/class group. Duplicate feature vectors that occurred in training were removed from testing. This prevents literal vector overlap but does not remove correlated traffic from the same scenarios.

| Metric | Measured value |
| --- | ---: |
| Accuracy | 0.9486 |
| Weighted precision | 0.9484 |
| Weighted recall | 0.9486 |
| Weighted F1 | 0.9484 |

| Class | Precision | Recall | F1 | Test rows |
| --- | ---: | ---: | ---: | ---: |
| Benign | 0.9751 | 0.9830 | 0.9791 | 7,299 |
| Botnet | 0.9094 | 0.9886 | 0.9474 | 264 |
| Brute force | 0.9873 | 0.9484 | 0.9675 | 1,474 |
| DDoS | 0.8688 | 0.8653 | 0.8671 | 1,500 |
| DoS | 0.8959 | 0.9007 | 0.8983 | 1,500 |
| Port scan | 0.7969 | 0.7247 | 0.7591 | 287 |

Confusion matrix, rows = true class and columns = predicted class, in order **Benign, Botnet, Brute force, DDoS, DoS, Port scan**:

```text
             Benign Botnet Brute DDoS  DoS  Scan
Benign         7175    17    18   33    7    49
Botnet            3   261     0    0    0     0
Brute force      67     9  1398    0    0     0
DDoS             49     0     0 1298  149     4
DoS               2     0     0  147 1351     0
Port scan        62     0     0   16    1   208
```

**Evaluation limitations:** This is a later-row holdout within each source file and label, not a held-out day, capture, network or organization. Attack scenarios from the same day remain correlated. Class capping shifts prevalence. Because CICFlowMeter produced the training CSVs and a separate Scapy implementation extracts inference features, exact numerical equivalence has not been verified against matched raw PCAPs. The model can still make predictions from compatible named fields, but these scores should not be quoted as accuracy on new packet captures. The short seven-feature schema also excludes ports and payload information. CSVs and model artifacts are ignored by Git and can be regenerated with the README commands.

Files added: `datasets/fetch_cicids2017.py`, `ml/schema.py`, `ml/train.py`, `backend/app/detection.py`, local `ml/artifacts/model.joblib`, `ml/artifacts/metrics.json`, the AI page in `frontend/src/advanced-pages.jsx`, and `backend/tests/test_model.py`. Re-run training with the PowerShell command in the root README. Tests check schema agreement and that local decision-path contributions sum to the forest probability.

## Phase 4 — Replay, alerts, analytics and reports

An imported capture can be replayed over `/api/ws/monitor` at 150 ms per flow. WebSocket messages include packet headers, analyzed flows, replay progress and completion; capture import and model reruns broadcast dashboard refresh events. Replay reads persisted data; it does not inject packets onto a network. The monitoring page shows streamed flows and packet headers, protocol mix, and flagged-flow timeline. Each non-benign model result creates a persistent alert with source/destination, timestamp, category, confidence and severity. Its status can be updated from **New** to **Investigating** or **Resolved**. Analytics presents protocol, temporal, category, top-IP, packet-size and saved model-evaluation charts. CSV and PDF downloads are real generated files; sample-mode exports carry explicit fixture labels. Flow inspection shows measured features, model confidence, positive/negative local contributions and defensive follow-up suggestions.

Validation: 22 backend tests exercise the PCAP → packet/flow → model → database → detection → alert/report path, plus replay event counts, packet-size buckets and status transitions. Six frontend component tests and the production build pass. A browser walkthrough checked the dashboard, upload, packet and flow details, model results, WebSocket replay, alert update, analytics, CSV download, and console errors. The API serves `/docs` for manual endpoint checks. The synthetic PCAP is for functional verification only; it does not validate classifier truth. For reviewer demonstrations, import an authorized real capture for real traffic values and clearly distinguish model predictions from confirmed attacks.

Files added or modified: `backend/app/advanced.py`, `backend/app/models.py`, `backend/app/main.py`, `frontend/src/App.jsx`, `frontend/src/advanced-pages.jsx`, `frontend/src/pages.jsx`, `frontend/src/components.jsx`, `frontend/src/styles.css`, `frontend/vite.config.js`, `frontend/src/api.js`, and pipeline tests.

Limitations: Replay is accelerated and grouped by flow, so it may not preserve original cross-flow packet interleaving or timing. Active replay state is in memory. Alert changes are local SQLite records. The single-user localhost app has no authentication or production hardening. Large uploads are intentionally rejected. The production JavaScript build gives a non-failing bundle-size warning; lazy chart loading is future optimization. No optional live interface capture or anomaly-only Isolation Forest has been implemented.

## Screenshots

Browser screenshots from FlowTwin: [dashboard](screenshots/integrated-dashboard.png), [PCAP and packet browser](screenshots/integrated-traffic.png), [model results](screenshots/integrated-detection.png), [WebSocket replay](screenshots/integrated-monitoring.png), and [analytics](screenshots/integrated-analytics.png). They use the nine-packet **synthetic parser demonstration** and an installed model. Any model category shown for that synthetic capture is a model output, **not a verified attack label**. The [Phase 1 dashboard screenshot](screenshots/phase-1-dashboard.png) preserves the earlier project branding for historical comparison.
