# Genuine live monitoring

FlowTwin can capture actual traffic from an explicitly selected local network adapter without uploading a PCAP. The **Live interface capture** tab uses Scapy `AsyncSniffer`; **Saved-PCAP replay** plays back previously imported data. Replay never captures or transmits network traffic.

## Windows setup

1. Install [Npcap](https://npcap.com/#download) from its official installer. Install its WinPcap-compatible API support if offered. A Windows driver installation requires administrator approval; FlowTwin does not install or elevate drivers itself.
2. Restart the backend after installing Npcap. If Npcap was installed with access restricted to administrators, start the backend from an elevated PowerShell window. Otherwise use the capture permissions configured by your administrator. Permission and adapter-open failures are shown in Monitoring.
3. Install the existing dependencies. No additional Python or npm package is needed for live capture:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
Set-Location frontend
npm.cmd ci
Set-Location ..
```

4. Run **one backend worker**, bound to loopback. Multiple workers or multiple backends sharing this database are unsupported: capture ownership and WebSocket subscribers belong to one process.

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --workers 1
```

In a second terminal:

```powershell
Set-Location frontend
npm.cmd run dev
```

Open [FlowTwin](http://127.0.0.1:5174/#/monitoring). Use the documented port 5174; live controls allow only local peers, loopback Host headers, and the localhost/127.0.0.1 browser origins on ports 5174 and 8000. There is no remote control or automatic interface selection. Keep the API on loopback; it is not an authenticated public service.

## Run a capture

1. Turn **Sample data mode off** in Settings.
2. Open **Live Monitoring → Live interface capture**.
3. Explicitly select your authorized **Wi-Fi or Ethernet** adapter by its name/address. Do not select an adapter you do not have permission to monitor. The application captures traffic visible to that adapter with promiscuous mode disabled; it cannot see every device's traffic on a switched/encrypted network.
4. Select **Start monitoring**. Browse a website or use an existing application normally to produce traffic. Packet rate, IP-layer bandwidth, protocol counts, active flows, recent structured headers, and connections update via WebSockets about every 500 ms, subject to processing capacity.
5. Completed flows go through the installed seven-feature Random Forest automatically. Non-benign results create persisted alerts. An active flow stays **unanalyzed** until completion. Quiet or long-lived flows complete at the shared 120-second boundary; TCP FIN/RST ends a flow before another same-key packet is processed. Stop also completes remaining flows.
6. Select **Stop monitoring**. The status changes to **stopping** while intake closes, the queue drains and remaining flows are saved/classified. Wait for **stopped**. Start and interface selection remain disabled during draining.

Capture continues across page navigation, tab switches, and viewer disconnections. Stop it explicitly. Sample mode cannot be enabled during a live session. Graceful backend shutdown also stops/drains capture. A backend crash or power loss can lose the current uncommitted batch and queue; startup marks surviving running-session records **interrupted**. Persisted partial flows remain visibly unanalyzed and are not silently classified as completed.

No model is required to measure and save traffic. If `ml/artifacts/model.joblib` is absent, completed flows stay **unanalyzed** and no ML alerts are invented. Model/schema failures are shown as model errors and counted; captured statistics are retained. Use the existing documented training workflow separately if predictions are needed. No model is retrained or changed by live monitoring. Predictions require analyst confirmation.

## Storage and source labels

- `captures.source` distinguishes `live` from `pcap`; sample flows remain isolated through `is_demo`.
- The additive `live_sessions` table records adapter identity, start/stop time, status, errors and counters. Existing tables are not rewritten or destructively migrated.
- `flows`, `flow_data`, `packets`, `detections` and `alerts` are reused. Active flow statistics are checkpointed with `complete=false`; finalized statistics include `complete=true` and `completion_reason`.
- Live packet rows contain capture/flow IDs, UTC timestamps, source/destination IPs and ports, protocol, IP packet size, TCP flags and forward/backward direction. The capture ID links these headers to the live session's interface. Metadata is accessible through the existing paginated packet API, ready for a future inspector. No new inspector or raw-payload archive is implemented.
- Flow APIs expose `traffic_source` and `capture_id`; Network Traffic, flow analysis, and reports distinguish the input source. CSV labels each row; PDF includes input labels. Only imported PCAPs can start PCAP replay.
- SQLite and metadata remain local and unencrypted. Disk usage grows with saved traffic; monitor free space and end sessions before storage fills. There is no automatic deletion or retention policy in this feature.

## Bounds, rates and drops

- Sniffer storage is disabled (`store=False`). Its callback extracts structured metadata and pushes it to a thread-safe queue of **4,096** entries. It never schedules one event-loop task per packet.
- A separate worker processes at most **256 packets per batch**, persists them transactionally, and holds constant-size running statistics for at most **5,000 active flows**. It retains no per-flow packet list. Finalizations are batched, with expiration continuing against packet time under backlog and wall time when caught up.
- New conversations exceeding the active-flow limit are dropped instead of changing flow segmentation. Queue overflow, capacity drops, and persistence losses are tracked. `dropped_packets` is total application loss; `capacity_dropped_packets` and `persistence_dropped_packets` identify subsets. Unsupported protocols and malformed packets have separate counters.
- Packet rate and bandwidth count **processed supported packets/IP-layer bytes**, not Ethernet overhead or traffic lost before processing. Active-flow and lifetime counters are based on committed data.
- Scapy does not provide portable Npcap/kernel drop statistics through `AsyncSniffer`. `driver_dropped_packets=null` means **unknown**, not zero. The application counters cannot measure packets lost before the callback.
- Each of at most **8 WebSocket viewers** has a **32-message queue**. Slow viewers discard older updates and receive a cumulative `stream_dropped` count. A send taking over one second disconnects that viewer; capture and persistence continue. Live snapshots include bounded recent lists (15 packets, 50 flows, 20 alerts), and reconnecting receives the current state. Saved data remains available through REST.

## API

| Endpoint | Meaning |
| --- | --- |
| `GET /api/live/interfaces` | Availability, Npcap/setup errors and adapter IDs/names/addresses |
| `POST /api/live/start` | JSON `{ "interface_id": "<ID from interfaces>" }`; waits for driver readiness |
| `GET /api/live` | Current status, rates, totals, drops and bounded recent metadata |
| `POST /api/live/stop` | Requests safe stop/drain; poll status or watch WebSocket for `stopped` |
| `GET /api/live/sessions` | Latest 50 persisted session summaries |
| `WS /api/ws/monitor` | Initial `connected` message with `live` and `replay`, then `live_snapshot` messages with `source="live"` |

Existing replay event names (`packet`, `flow`, `replay_started`, `replay_completed`) retain `source="pcap_replay"` on packet/flow events. Live snapshots cannot be mistaken for replay events. API start rejects sample mode, missing/unknown interfaces, foreign origins, remote peers, and concurrent sessions. Stop remains available locally after a startup error.

## Tests and Windows smoke check

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests -q
Set-Location frontend
npm.cmd test
npm.cmd run build
```

Automated tests inject synthetic Scapy packets and a fake sniffer into the actual capture worker. They cover feature parity, constant-space statistics, queue/capacity loss, expiration with/without backlog, safe stop, inference/driver/storage failures, source isolation, alerts, local request checks, bounded WebSockets, HTTP start/stop and streamed results. Existing PCAP/replay/export tests remain in place. These tests do not install Npcap or prove hardware capture.

On Windows with Npcap, manually select a real adapter and start a session, generate normal authorized traffic, check nonzero packet/byte counters and source/destination headers, then stop. Confirm the adapter closes, status becomes stopped, the session and packet rows survive a backend restart, and the same data is labeled **live** in Network Traffic/reports. With a model installed, confirm a completed flow has a detection (a benign prediction will not generate an alert). Also verify the separate replay tab still handles an imported PCAP. Never generate attacks just to test the UI.

## Troubleshooting

- **Npcap required / no adapters:** install Npcap and restart the backend; verify your adapter is enabled.
- **Access denied:** use capture permissions granted by your administrator; an administrator-only Npcap installation requires an elevated backend terminal.
- **No packets:** confirm you selected the adapter actually carrying the traffic. Unsupported link/protocol traffic is counted separately. Loopback traffic is visible only on the appropriate explicitly selected adapter.
- **Drops increase:** incoming traffic exceeds processing/storage capacity. End the session and use a quieter authorized interface; driver losses may be additional and unknown.
- **Stopping takes time:** queued metadata and active flows are being persisted and classified. Do not start a second backend; wait for the final status.
- **Driver did not stop / storage error:** review the error, preserve the database, fix permissions/storage, and restart the backend before another capture.
