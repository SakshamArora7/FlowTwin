# FlowTwin V2 packet inspector

Open [Packet Inspector](http://127.0.0.1:5174/#/inspector), turn sample mode off, and select a capture. Existing capture controls remain in Live Monitoring; PCAP import remains in Network Traffic. No model or Wireshark installation is required for packet inspection.

## Reference and architecture

The implementation follows the independently researched patterns in [the official Wireshark source](wireshark-reference.md): separate packet/field/byte views, byte-range provenance, filter compilation before application, and per-direction TCP sequence tracking. No Wireshark source, assets, Qt components, or GPL library code was copied or linked. Existing dependency licenses still apply.

```text
AsyncSniffer -> original-byte snapshot + existing flow metadata -> bounded live queue
                                                               -> existing flow/ML worker
                                                               -> inspection writer
PCAP reader -> ordered frames + existing bidirectional flow analysis -> inspection writer

SQLite: captures / flows / detections / alerts (existing)
        inspection_captures / inspection_packets / packet_bytes / tcp_streams (additive)
                            |
           local-only inspector API, parameterized SQL, bounded results
                            |
       React packet list <-> selected protocol field <-> hex/ASCII bytes
                            |
               TCP follow / linked flow / security alert
```

Inspection records permit packets without an ML flow, including ARP and unsupported protocols. The original seven-feature model contract, flow timeouts, first-observed direction and TCP termination rules are unchanged. TCP conversations have their own identities, so a final ACK after FIN can remain in the same conversation even when the existing ML flow assembler starts another flow.

New PCAP imports accept ARP-only captures. Capture packet totals include all original records, while dashboard flow metrics continue to measure supported network flows. Inspection packet numbers preserve original PCAP order. The existing packet-header endpoint remains compatible; the inspector also includes packets that the ML extractor does not process.

## Three panes

- **Packets:** 50 or 100 rows per page, server-side sorting and display filtering, stable packet IDs and protocol colors. Select the packet-number button to inspect it.
- **Protocol details:** expand/collapse observed protocol layers and select a field. Fields have explicit offsets and lengths into original bytes; no string searching or reconstructed headers are used for highlighting.
- **Packet bytes:** hexadecimal and printable ASCII, 256 bytes per page. Selecting a field jumps to its byte page and highlights both representations. Missing bytes and unsupported/truncated decoding are identified explicitly.

Dissection supports Ethernet/VLAN, ARP, IPv4 with options, IPv6 with bounded extension traversal, TCP with options/flags/sequence/acknowledgment, UDP, ICMP/ICMPv6, basic DNS records, and observable HTTP/1 request/response/header lines. Linux cooked and loopback link framing are supported where recognized by Scapy's registry. Unknown link/protocol types remain opaque. TLS record headers may be shown, but encrypted content is never presented as decrypted HTTP. HTTP split across TCP packets is available through bounded TCP following, not a full application reassembly engine.

## Display-filter subset

Draft and applied filters are separate. Invalid filters produce a 422 error and leave the last successful packet list visible. Filters are tokenized, type-checked and compiled into SQL expressions with bound values; Python `eval` and SQL interpolation are not used. This is a documented subset, **not the complete Wireshark display-filter language**.

| Use | Examples |
| --- | --- |
| Protocol presence | `tcp`, `udp`, `arp`, `ip`, `ipv6`, `icmp`, `dns`, `http`, `tls` |
| Boolean operators | `tcp && !http`, `dns or arp`, `(tcp || udp) && frame.len > 100` |
| Exact addresses | `ip.addr == 10.0.0.1`, `ip.src != 10.0.0.1`, `ipv6.dst == 2001:db8::2` |
| Ports | `tcp.port == 443`, `udp.dstport == 53`, `tcp.srcport >= 1024` |
| TCP flags | `tcp.flags.syn`, `tcp.flags.ack == true`, `tcp.flags.fin == 1`, `tcp.flags.rst == 0` |
| Length / number | `frame.len > 1500`, `frame.number >= 20` |
| Time ranges | `frame.time_relative >= 2 && frame.time_relative <= 10` |
| UTC epoch range | `frame.time_epoch >= 1700000000 && frame.time_epoch < 1700000060` |
| Conversation | `tcp.stream == 12` |

Operators: `== != > >= < <=`; equality/inequality only for addresses and flags. Precedence is parentheses, negation, AND, OR. Protocols are case-insensitive. Address family must match `ip` (IPv4) or `ipv6`. CIDR, functions, regex, arbitrary field names and full Wireshark coercion rules are unsupported. For paired `.addr`/`.port`, equality matches either endpoint; inequality excludes a match on either endpoint. Stream IDs are FlowTwin's database IDs, not Wireshark's zero-based stream numbers. Time is relative to the earliest stored packet in that capture. Limits: 1,024 characters, 128 tokens, 12 nesting levels; invalid values fail closed.

## Follow TCP conversations

Select **Follow TCP stream** on a TCP packet. The packet table becomes conversation-scoped; the follow view offers both directions or either direction and text/hex output. Packet provenance links return to constituent packets. Per-packet sequence/acknowledgment numbers and SYN/ACK/FIN/RST flags are available in the protocol tree and summary.

Payload is ordered by TCP sequence, including wraparound. Duplicate/retransmitted ranges are removed, conflicting overlaps keep the first captured bytes with a warning, and missing ranges are annotated rather than zero-filled. Each direction is bounded to **64 KiB output**, scans at most **1,000 packets** per conversation request and reads at most **8,192 payload bytes per packet**. Missing raw bytes, scan/output limits and fragmented/truncated IP payloads are explicit warnings. IP fragmentation is not reassembled. A midstream capture cannot recover data sent before capture began. Hex output contains only retained bytes; consult gap annotations rather than treating it as a byte-perfect stream image.

Conversation association uses bidirectional endpoints, initial SYN/sequence, connection reuse after closure, and the existing 120-second inactivity boundary. Up to 5,000 conversation keys remain in live memory; older keys are evicted. Very long idle/reused conversations may therefore appear as separate stream IDs. This intentionally does not recreate all Wireshark TCP analysis.

## Raw data, retention and compatibility

**New behavior:** inspector-enabled captures retain original packet bytes, potentially including credentials, cookies, DNS names and cleartext application content. They remain in the local SQLite database, unencrypted. Never share that database casually or expose the API to an untrusted network. Data is shown as escaped React text and bytes, never executed, resolved remotely, or uploaded to another service.

- At most **65,535 original bytes per frame** and **64 MiB raw bytes per capture/session** are retained. After the capture quota, metadata and flow/ML processing continue; affected packets show `retention_limit`.
- The sniffer callback only snapshots bytes and current metadata. Decoding and database writes occur in the existing worker. Live raw bytes occupy at most **16 MiB** of the bounded 4,096-entry queue, plus a 512-byte header fallback per entry. If the byte limit is reached, metadata continues but that frame's raw status is `queue_limit`.
- Raw BLOBs are separate from list/index rows; packet lists do not fetch them. Selected packet decoding and bounded follow queries run through synchronous FastAPI worker endpoints. Browser packet rows and byte rendering are paginated.
- The existing WebSocket channel sends committed `packet_updates`/`live_snapshot` invalidation signals, not raw payloads. Inspector list/follow updates are throttled; sockets reconnect with backoff. Background updates preserve packet/field selection and filter errors.
- Raw data is not automatically deleted. Total disk use can grow across sessions. Monitor free space and stop capture before storage fills.
- Existing tables and records are preserved. Historical live captures contain headers only; neither their payload nor exact original capture order can be recovered. The inspector shows a metadata-only notice and numbers them by stored timestamp. Reimport an old PCAP to obtain complete frame inspection. Original uploads were retained previously, but were not reliably linked to per-packet byte offsets, so the application does not guess a file mapping.

New tables are created automatically at backend startup. No model retraining, destructive migration, Wireshark dependency, or new Python/npm dependency is needed. The API remains a local, single-worker workspace. If updating while capturing, stop/drain the live session before restarting the backend; new sessions use the new raw-data path.

## API and navigation

| Endpoint | Purpose |
| --- | --- |
| `GET /api/inspector/captures` | Latest 50 captures, inspection availability and retention notices |
| `GET /api/inspector/packets?capture_id=...` | Filtered/sorted/paged summaries; optional `flow_id` and `stream_id` |
| `GET /api/inspector/packets/{id}` | Original retained bytes as hex, protocol ranges, linked flow/detection/alerts |
| `GET /api/inspector/streams/{id}` | Bounded bidirectional TCP follow result and provenance |

Sort fields: `number`, `timestamp`, `source`, `destination`, `protocol`, `length`; order `asc`/`desc`; page size 1–100. All inspector endpoints enforce local peer/Host/Origin checks and real data mode. Historical metadata uses negative packet IDs, distinct from new positive inspection IDs.

Flow dialogs link to `#/inspector?capture=<id>&flow=<id>`; direct packet navigation also accepts `&packet=<id>`. Inspector packets link back to the flow dialog and saved alerts. Existing alerts, reports, detection and replay features remain separate and operational.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests -q
Set-Location frontend
npm.cmd test
npm.cmd run build
```

Tests cover byte offsets/options/extensions, malformed/truncated framing, DNS pointer bounds, HTTP/TLS distinctions, typed filters and invalid input, sorting/paging, legacy metadata, raw quotas, ARP-only imports, live frame updates, stream association/reuse, sequence ordering/wrap, overlaps/gaps, fragmentation warnings, and UI synchronization/reconnects. Existing live monitoring, PCAP, ML contract, alert and report tests remain included. A trained-model artifact is still required for model-dependent runtime checks.
