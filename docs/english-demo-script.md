# FlowTwin demo: English on-screen text, English narration

The video uses real application screenshots and expanded English voiceover. The spoken script follows each English chapter title.

## 1. What is FlowTwin?

Welcome to FlowTwin. This project turns a saved network packet capture into information that a student or security analyst can inspect. It parses packets, joins the two directions of a conversation into flows, and uses a trained machine-learning model to highlight traffic worth investigating. A prediction is an investigative signal, not proof that an attack occurred.

## 2. How the system works

Here is the complete system path. A React dashboard communicates with a FastAPI backend. Scapy reads the packet capture and extracts network headers. SQLite stores captures, packets, flows, detections, and alert status. A Random Forest model evaluates selected flow features. The dashboard then presents the results as tables, charts, alerts, and downloadable reports.

## 3. Sample mode vs imported data

FlowTwin starts in sample mode. Those fixed example records demonstrate the interface, and their labels are not AI predictions. For measured traffic, I turn sample mode off in Settings and import a PCAP file. From that point, packet values and flow statistics come from the imported capture. Explaining this distinction prevents the demonstration from confusing fixture data with real analysis.

## 4. Importing a PCAP file

The Network Traffic page accepts PCAP and PCAPNG files within processing limits. Scapy reads each supported packet's source and destination IP address, transport ports, protocol, timestamp, size, and TCP flags. The packet table lets us inspect the evidence behind a flow. The bundled walkthrough capture contains nine generated packets; it tests the parser, but it has no verified attack label.

## 5. Bidirectional flow grouping

A flow is a network conversation grouped by protocol and its two endpoint address-and-port pairs. A packet from A to B and its reply from B to A can belong to the same flow. The first observed packet sets the forward direction. Timeouts and TCP closure split a long conversation into new flows. This bidirectional grouping is the idea behind the FlowTwin name.

## 6. Features measured from packets

After grouping packets, FlowTwin measures duration, forward and backward packet counts and bytes, packet-size statistics, packet rate, inter-arrival time, and TCP flag counts. The detail panel displays these measured values. Exactly seven ordered features are passed to the model: duration, two directional packet counts, and FIN, SYN, RST, and ACK flag counts. The saved model checks that inference uses this expected feature schema.

## 7. Training the AI model

The model was trained from selected labeled CIC-IDS2017 flow tables. Training cleans the data, handles missing values with a median imputer, and fits a Random Forest with one hundred and twenty trees. The six supported categories are Benign, Botnet, Brute force, DDoS, DoS, and Port scan. The installed training run used fifty thousand one hundred and seventeen rows. Dashboard sample fixtures were never used for model training.

## 8. Predictions and explanations

For each imported flow, the model returns a category and a probability estimate. The interface also shows severity and a local explanation derived from the decision paths inside the forest's trees. Those feature contributions explain why the model voted as it did. They do not establish that a host is compromised. Suspicious predictions should be checked against packet evidence, logs, and network context.

## 9. What the evaluation means

The measured weighted F-one score was ninety-four point eight four percent on twelve thousand three hundred and twenty-four held-out rows. This is a result for that selected dataset split, not a guarantee on a new network. Related scenarios can occur in both training and testing. The source tables were produced with CICFlowMeter, whereas this application extracts PCAP features with Scapy; exact numerical equivalence has not been established.

## 10. Monitoring uses PCAP replay

In Live Monitoring, Start Replay sends saved packet headers and already analyzed flows through a WebSocket. The page updates as the events arrive and shows protocol distribution and flagged connections. This is accelerated playback of an imported PCAP. It is not direct interface sniffing, and it does not transmit packets onto the network. Replay makes the processing sequence easy to show during a short classroom demonstration.

## 11. Alerts, analytics and reports

A non-Benign model result creates a persistent security alert. Its status can move from New to Investigating and then Resolved. The analytics page shows traffic over time, protocols, source IPs, categories, packet sizes, and model metrics. Reports can be exported as CSV or PDF. Sample-mode exports are labeled separately so example records are never presented as actual detections.

## 12. Live demo for your teacher

For a live teacher demonstration, first explain the problem and dashboard. Turn off sample mode and import the provided synthetic PCAP. Show how packet records become a two-way flow, then open the AI result and feature explanation. Start replay, inspect the alert workflow, and export a report. Finish by stating the limits honestly: the bundled capture has no verified attack labels, and a model score begins an investigation rather than ending one. Thank you.
