# Packet inspector implementation plan

**Goal:** Add a Wireshark-inspired inspection workspace for live traffic and imported captures without changing ML features or capture ownership.

**Reference:** [Official source research](../../wireshark-reference.md), pinned upstream commit e80410714e8292569a41db153abbbdc0d7d5edc7. Independently implement behavior; copy no Wireshark code/assets.

## Architecture and data contract

- Keep existing Capture, PacketRecord, Flow, Detection, Alert and live worker. Add inspection summary, raw-byte, capture-retention and TCP-conversation tables; no destructive migration.
- PacketRecord remains the existing flow-analysis record. Inspection records additionally accept ARP and unsupported packets without inventing flows. Raw bytes are separate from list projections.
- Store original link type and bounded original bytes for new packets: 65,535 bytes/frame, 64 MiB/capture raw retention, 16 MiB live raw queue. Continue metadata/ML after a raw retention/queue limit and report missing/truncated bytes honestly. Raw payloads are local sensitive data and never included in WebSocket events.
- Historical packet records remain browsable as metadata-only. Original bytes and exact original capture order were not retained; do not synthesize them. Reimport PCAPs for complete inspection.
- Decode selected packets on demand through Scapy, with explicit field byte ranges. Support Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP/DNS/observable HTTP; encrypted/unknown protocols remain opaque.
- Compile a bounded, typed display-filter subset into parameterized SQL. Native SQL handles sorting, counts, pagination and flow/stream association.
- TCP conversations use capture-scoped canonical endpoints, initial SYN/sequence and reuse boundaries; bounded follow results order per-direction payload by sequence and show gaps/retransmissions. Do not claim full Wireshark/TLS support.
- React packet table, field hierarchy and paged hex/ASCII pane share selection state. Preserve FlowTwin styles, add flow/alert navigation and a separate follow-stream view. Existing capture controls remain in Monitoring.
- Existing WebSockets invalidate packet list pages on committed updates. Never stream raw bytes or retain unbounded browser rows.

## Tasks

- [x] Pure dissection + byte-range tests (independent workstream).
- [x] Typed filter parser + SQL tests; additive models and capture/stream writer.
- [x] Offline and live pipeline integration, local-only APIs and bounded follow results.
- [x] React inspector, integration links and UI tests (independent workstream).
- [x] Regression tests, review, browser proof and setup/filter/retention documentation.

## Acceptance and safety

Test protocol/option/truncation offsets, malformed filters, IP/port/flags/length/time filters, sorting/paging, bidirectional stream reuse and retransmissions/gaps, live updates, old metadata-only rows, byte-retention limits and local/sample isolation. Re-run existing PCAP/live/ML/alert/report tests. Do not train a model or automatically start another capture. If restarting an active backend is necessary, stop/drain its session first.

## Verification results

- Backend: 75 passed, 2 skipped (no installed model artifact); existing monitoring/import/replay/alerts/CSV/PDF regressions pass.
- Frontend: 21 passed; production build succeeds.
- Browser: synthetic PCAP with TCP/HTTP/DNS/ARP, exact IPv4 source-byte highlights, SYN filtering, bidirectional HTTP follow.
- Large legacy capture: 488,323 packets, bounded 50-row page; optimized redundant numbering scans from about 7.5 seconds to about 2 seconds on this machine. This is an observation, not a throughput guarantee.
- Previous real live session was stopped/drained and saved before restart. No new interface was selected or automatically captured during inspector verification. Live integration is covered with injected Scapy packets and the actual worker/WebSocket path.
- Review fixes: fragment/truncation warnings propagate into follow completeness; open streams and completed model/alert context refresh; invalid filters and field selection survive background refresh; valid filters reconcile selection.
