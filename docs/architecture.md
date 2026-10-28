# FlowTwin architecture

```text
Browser (React / Vite / Tailwind / Recharts / Framer Motion)
      ├─ REST /api ─────► FastAPI ─► SQLAlchemy ─► SQLite
      │                         ├─ Scapy PCAP parser and bidirectional flow assembler
      │                         ├─ Joblib Random Forest pipeline
      │                         ├─ persisted detections and alert workflow
      │                         └─ CSV / ReportLab PDF exporter
      └─ WebSocket /api/ws/monitor ─► live snapshots plus replay of persisted PCAP packet headers and flows

CIC-IDS2017 Parquet mirror ─► cleaning / temporal-within-class holdout ─► Joblib model + metrics
                                 ↑ shared ml/schema.py feature contract ↓
                           PCAP feature extraction in backend/app/traffic.py
```

The Vite development proxy sends `/api` to localhost:8000 and upgrades `/api/ws/monitor` to the FastAPI WebSocket server. SQLite is intended for one local student user. Imported captures are stored in ignored `uploads/`, packet headers in `packets`, flow records in `flows`, extracted statistics in `flow_data`, classifier results in `detections`, and workflow state in `alerts`. Demo fixtures live in the `flows` table with `is_demo=true`; all real-data endpoints verify the selected mode. Settings persist in `settings`. `captures` records file metadata and packet/flow counts.

## Packet and flow definitions

Scapy reads PCAP/PCAPNG offline. The parser accepts IPv4 or IPv6 with TCP, UDP, or ICMP. It records timestamps in UTC, IPs, ports (zero for ICMP), protocol, IP-layer packet size, TCP flags, and observed direction. The flow/ML path uses payload sizes rather than content. Packet Inspector V2 separately retains bounded original bytes locally for inspection; packet content is never executed. Historical captures remain metadata-only where original bytes were not retained.

A bidirectional key is protocol plus the unordered pair of `(IP, port)` endpoints. The first observed packet sets the forward direction. A new flow begins after 120 seconds of inactivity, after 120 seconds of elapsed flow time, or after the next packet following a TCP FIN/RST. Within each flow, forward/backward packet counts and bytes, duration, packet-size min/max/mean/std, packet rate, inter-arrival mean/std, and TCP flag counts are calculated from actual packet records. This implementation uses a bounded in-memory analyzer: at most 25 MB uploaded, 50,000 raw packets, and 5,000 flows. It rejects excess input rather than saving a partial analysis.

**Important extraction limit:** The seven model features use CIC-IDS2017 column names and units. The parser was written separately from CICFlowMeter. It has not been compared packet by packet with the original extractor on the same labeled PCAP. Exact feature-value equivalence, especially flow segmentation and packet interpretation, is not established. The model is an educational signal; findings need analyst confirmation.

## Shared model feature contract

`ml/schema.py` defines the ordered fields:

1. `Flow Duration` — microseconds
2. `Total Fwd Packets` — count
3. `Total Backward Packets` — count
4. `FIN Flag Count` — count
5. `SYN Flag Count` — count
6. `RST Flag Count` — count
7. `ACK Flag Count` — count

The training script selects these exact named columns from the source tables, cleans non-finite values, and fits a median imputer followed by a Random Forest. The saved Joblib artifact includes the schema version and ordered feature list. Inference refuses a mismatched schema or a flow missing any field. Import does not silently assign labels if no model is installed. The explanation code computes each feature's average change to the selected class probability along the decision path of every forest tree. It is a local, model-derived explanation of the vote, not evidence of an actual attack.

## API routes

| Route | Purpose |
| --- | --- |
| `GET /api/health` | Database readiness, current phase and model status |
| `GET/PUT /api/settings` | Persist sample mode and refresh interval |
| `GET /api/overview?hours=1/6/24` | Dashboard aggregates relative to the latest selected record |
| `GET /api/flows`, `GET /api/flows/{id}` | Search, filter, paginate and inspect selected-mode flows |
| `POST /api/captures` | Validate, parse, classify and save an uploaded PCAP |
| `GET /api/captures`, `GET /api/captures/{id}/packets` | Capture and packet browsing |
| `GET /api/flows/{id}/analysis` | Measured statistics and model explanation |
| `POST /api/captures/{id}/analyze` | Classify a previously imported capture with the installed model |
| `GET /api/model`, `GET /api/detections` | Measured evaluation and saved model results |
| `GET /api/analytics/packet-sizes` | Packet-size buckets from imported PCAP records |
| `GET /api/alerts`, `PATCH /api/alerts/{id}` | Saved alert list and New/Investigating/Resolved state |
| `GET /api/reports/csv`, `GET /api/reports/pdf` | Local report exports with explicit data-source labels |
| `GET /api/replay`, `POST /api/captures/{id}/replay` | Accelerated PCAP replay control |
| `WS /api/ws/monitor` | Import/analysis refresh signals, replay state, packet-header and analyzed-flow events |

Replay broadcasts persisted packet headers grouped by flow and pauses 150 ms per flow. It is a demonstration of streaming already analyzed PCAP data, not live interface capture, and it does not replay packets onto the network. This grouping may not reproduce original interleaving across simultaneous flows. The active replay state is in process memory and resets on backend restart.

## Local limits and safety

The backend binds to `127.0.0.1` in the documented run command and is not an authenticated multi-user service. CORS is restricted to the documented frontend origins. SQLite and uploaded files are unencrypted. Do not expose the API to the internet or import traffic without permission. A live interface is opened only after a local Start request explicitly selects an enumerated adapter. No packets are transmitted and no payload is executed. See [live monitoring](live-monitoring.md) for setup and capture bounds. Model metrics are shown with evaluation caveats, and sample fixtures are separated from true imports and visibly marked in reports.


## Live interface capture

```text
Explicit local interface selection -> AsyncSniffer (store=False, promisc=False)
  -> structured headers -> bounded queue (4,096)
  -> dedicated worker: shared keys, FlowStats, timeouts and TCP termination
  -> SQLite batches: packets + active statistics -> completed flows -> existing model/alerts
  -> bounded snapshots every 500 ms -> existing WebSocket -> React Live Monitoring
```

The capture worker is separate from offline PCAP analysis. Live sessions reuse Capture with source=live, existing flow/packet/detection tables, and the additive live_sessions table. A single process owns capture; start/stop are serialized. Model inference and SQLite work stay off the ASGI event loop. Shared online statistics retain no packet list; SQL dashboard aggregation and packet/flow pagination avoid loading historical captures into memory. Stop closes intake, drains the queue, finalizes active flows, commits, then publishes stopped. Restart marks unfinished sessions interrupted. WebSocket consumers have bounded queues and cannot stall capture. Genuine capture and saved-PCAP replay are separate UI choices and event types.

## Packet Inspector V2

The inspection path adds inspection_captures (retention counters), inspection_packets (list/filter projections and flow/conversation associations), packet_bytes (separate original-byte BLOBs), and tcp_streams (bidirectional conversations). No existing tables are destructively migrated. Live callbacks snapshot bounded original bytes and original link type; the worker performs decoding, association and persistence. PCAP import preserves original frame order and additionally indexes ARP/unsupported frames without inventing ML flows.

Local-only /api/inspector routes compile a typed display-filter subset into parameterized SQLite queries, paginate summaries, decode selected frames with explicit field ranges, and return bounded per-direction TCP reconstruction with missing-range/fragmentation warnings. React synchronizes packet, field and hex/ASCII panes, invalidates committed pages through existing WebSockets and links to existing flow/detection/alert views. See [complete inspector contract and limits](packet-inspector.md) and [official Wireshark research](wireshark-reference.md).
