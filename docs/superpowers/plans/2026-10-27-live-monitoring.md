# Live monitoring implementation plan

**Goal:** Capture an explicitly selected local interface with AsyncSniffer and stream genuine live statistics while preserving PCAP import and replay.

**Architecture:** One capture session per local, single-worker backend. A bounded thread-safe packet queue feeds a dedicated processing/database worker. Shared flow statistics and prediction persistence serve offline and live paths. WebSockets publish bounded snapshots independently of capture processing.

**Scope:** User requirements in this chat: live capture, current seven-feature inference, alerts, persistence, bounded memory, safe stop, local controls, Windows documentation. No inspector, payload retention, model training, automatic interface selection, or packet injection.

## Steps

- [x] Test and implement incremental statistics matching offline extraction, with the same key, direction, timeout and TCP rules.
- [x] Share prediction persistence; add an additive live-session table, source labels and handling of unanalyzed flows.
- [x] Test and implement interface enumeration, startup readiness, bounded capture intake, expiration, batched persistence, drop accounting, stop/drain and failure recovery.
- [x] Add local-only live APIs and bounded WebSocket delivery; flush on app shutdown and mark interrupted sessions on restart.
- [x] Add genuine live Monitoring controls and metrics, retain a separately labeled replay view, and test UI controls and events.
- [x] Document Npcap/permissions, limits, API contracts and Windows smoke testing. Run backend tests, frontend tests/build, and inspect the UI.

## Invariants and review focus

- Never start without a current explicitly selected interface, local peer/host and trusted browser origin.
- Never retain raw packet payloads or an unbounded packet/flow/event buffer.
- Never classify a partial flow as completed; finalized predictions use the unchanged feature contract.
- Stop capture intake before draining; do not report stopped until queued metadata and active flows are persisted.
- Report queue/capacity loss separately from unsupported traffic; driver loss is unknown unless exposed by the driver.
- No destructive migration: existing tables and model artifacts remain compatible.
- Preserve offline flow boundaries and analysis values, sample isolation, alert workflows and exports.

## Proof

Synthetic Scapy packets and an injected sniffer exercise the real processing path without capturing a user's interface. Windows hardware capture requires Npcap and an explicit interface selected by the user; do not start it automatically.

## Verification result

- Backend: 38 passed, 2 skipped (installed-model artifact tests).
- Frontend: 10 passed; production build passed.
- Existing PCAP import/replay, sample isolation, alert updates, and CSV/PDF tests passed.
- Reviewed and fixed expiration starvation under backlog, unbounded historical dashboard loading, final snapshot/HTTP ordering, and Stop/error cleanup races.
- Hardware capture was not started automatically. During the UI handoff, a physical Realtek Wi-Fi adapter was explicitly selected from the UI: genuine streaming was observed with over 1,700 processed packets, completed flows, and zero application drops at observation time. The session controls were left to the user. No trained-model artifact is installed, so runtime predictions remain unverified. Screenshots containing live metadata are stored outside the repository.
