# Presenting FlowTwin to your teacher

Watch the [expanded English video](flowtwin-demo-english.mp4) before presenting. An [English-screen version with Hindi narration](flowtwin-demo-english-screen-hindi-voice.mp4) is also available. Both use real application screenshots, explain the synthetic PCAP honestly, and cover the full packet-to-report pipeline. Read the [English script](english-demo-script.md) or [Hindi narration](hindi-demo-script.md) for practice.

## Explain it in one sentence

**FlowTwin reads an authorized packet-capture file, joins related packets into two-way network conversations, measures each conversation, and uses a trained machine-learning model to flag traffic worth investigating.**

“Twin” is the pair of directions in a conversation: a packet sent from A to B and a reply from B to A belong to the same bidirectional flow.

## What the application actually does

1. **Input:** You import a `.pcap` or `.pcapng` file. This is a saved recording of network packets. FlowTwin does not currently sniff a network interface.
2. **Packet analysis:** Scapy reads IP addresses, ports, protocol, timestamp, packet size and TCP flags. The app stores these headers and measured values, not packet payloads.
3. **Flow construction:** Packets with the same endpoint pair and protocol are joined in both directions until a timeout or TCP close. FlowTwin calculates duration, packet and byte counts, rates, size statistics, inter-arrival times and flag counts.
4. **AI classification:** A Random Forest trained on selected CIC-IDS2017 flow-table rows receives seven ordered flow features. It predicts one of Benign, Botnet, Brute force, DDoS, DoS or Port scan, with a probability estimate. The explanation panel shows real contributions from the model's tree paths.
5. **Review:** The dashboard, packet table, charts and alerts help a person inspect predictions. Non-benign predictions create alerts that can be marked New, Investigating or Resolved. CSV and PDF reports can be exported.
6. **Replay:** Live Monitoring streams saved packet headers and analyzed flows through a WebSocket at an accelerated pace. This is **PCAP replay**, not live interface capture and not packet transmission.

```text
Authorized PCAP → packet headers → bidirectional flows → measured features
               → trained Random Forest → predictions → dashboard, alerts and reports
```

## A five-minute demonstration

| Time | Show | Say |
| --- | --- | --- |
| 0:00–0:40 | Dashboard in sample mode | “The first screen uses labeled illustrative data so the interface can be explored safely. These are not AI results.” |
| 0:40–1:10 | Settings | “I will switch sample mode off. The next values come from a PCAP file parsed by the backend.” |
| 1:10–2:10 | Network Traffic → import `datasets/sample_capture.pcap` | “This small capture has nine synthetic packets for a dependable parser demonstration. Here are actual extracted packet headers and two-way flows.” |
| 2:10–3:00 | Open a flow, then AI Threat Detection | “The model uses the measured flow features and returns a category, confidence and feature contributions. The synthetic file has no verified attack labels, so its prediction is only an example of inference.” |
| 3:00–3:40 | Live Monitoring → Start replay | “The WebSocket streams saved packet and flow events. It is replay, not real-time sniffing.” |
| 3:40–4:20 | Security Alerts and Analytics | “Only non-benign predictions become alerts. I can change an alert's investigation status and inspect traffic and model charts.” |
| 4:20–5:00 | Reports | “I can export the saved analysis as CSV or PDF. I would verify any flagged traffic with other evidence before taking action.” |

To prepare, start both servers with the [README commands](../README.md). Have the [sample capture](../datasets/sample_capture.pcap) ready. If you have a permitted capture from a real network, use it for the substantive analysis and keep the synthetic file as a fallback. An alert is only created if the model predicts a non-benign category, so do not promise that every capture will produce an alert.

## What to say about the model result

The installed Random Forest was trained on **50,117** selected CIC-IDS2017 flow rows and evaluated on **12,324** held-out later rows from the same source files. Its measured weighted F1 was **94.84%**. This measures performance on that particular split, **not** reliability on an unseen network. The training tables came from CICFlowMeter, while the app extracts PCAP features with Scapy. Their exact numerical equivalence has not been established. A confidence value is the forest's estimated class probability, not proof of an attack.

If asked why you used a Random Forest: “It works well with tabular flow statistics, can represent nonlinear combinations of features, and lets me inspect how its trees contributed to a prediction.”

If asked what makes this a Computer Networks project: “The core is packet parsing and bidirectional flow construction using IP addresses, transport ports, protocols, timestamps, flags, timeouts and traffic statistics. The ML model consumes features derived from those network concepts.”

If asked what you would improve next: “I would compare Scapy and CICFlowMeter outputs on the same labeled PCAP, test on an entirely unseen capture day or network, calibrate model probabilities, and add authorized live capture through Npcap.”

## Keep these distinctions clear

- **Sample mode:** fixed illustrative dashboard records, never model predictions.
- **Synthetic sample PCAP:** generated packets that exercise real parsing and inference, without ground-truth attack labels.
- **Authorized real PCAP:** real recorded traffic; its extracted values are real, but a model prediction still needs investigation.
- **Evaluation score:** measured on selected CIC-IDS2017 tables; it is not a field-accuracy guarantee.
- **Live Monitoring:** a live UI stream of replayed saved events, not direct network sniffing.

For more technical answers, use the [viva questions](viva.md) and [architecture notes](architecture.md).
