# Viva questions and answers

**What problem does FlowTwin solve?** It organizes packet-capture evidence into searchable flows, applies a trained classifier to supported flow statistics, and gives a reviewer a place to inspect and track findings. It does not prove that a host is compromised.

**What is a packet? What is a flow?** A packet is one observed network unit with protocol headers and possibly payload. A flow groups packets sharing protocol and two endpoint address/port pairs in either direction within the defined timeout. The first observed direction is forward.

**Which OSI/TCP-IP information is used?** The parser reads IPv4/IPv6 addresses at the network layer, TCP/UDP ports and TCP flags at transport, ICMP message traffic, and timestamp/size from the capture record. It does not inspect or execute application payloads.

**How are reverse packets joined?** The key uses an unordered pair of `(IP, port)` endpoints plus protocol. A reverse packet matches the same key, then the stored first packet direction determines whether it increments forward or backward counters.

**Why a 120-second timeout?** It bounds flow lifetime and mirrors the commonly used CICFlowMeter flow-timeout setting. Inactivity and total elapsed time are both checked here. Exact equivalence to CICFlowMeter segmentation is not claimed without matched-PCAP verification.

**What data trains the model?** Five selected CIC-IDS2017 labeled flow tables from a public Parquet conversion of the UNB/CIC release. The repository records URLs and SHA-256 hashes. The synthetic sample PCAP and dashboard fixtures are never training data.

**Which features does the model use?** Flow duration in microseconds, forward and backward packet counts, and FIN/SYN/RST/ACK flag counts. The same ordered names and units are stored in the model artifact and checked during inference.

**Why Random Forest?** It works with nonlinear tabular feature interactions, offers class probabilities, trains on a modest CPU, and supports tree-path explanations. It is still only as reliable as the dataset, labels, and feature extraction.

**What do the measured evaluation metrics mean?** Accuracy is all correct predictions divided by all held-out rows. Precision measures how often a predicted class is correct; recall measures how many true rows of a class are recovered; F1 balances precision and recall. Weighted metrics average per-class results by test support. The confusion matrix shows each true-versus-predicted count.

**How was leakage limited?** The split holds out later rows within each source file/class group, the imputer is fit only on training rows, and identical feature vectors are removed from test if present in training. Related traffic from the same attack scenario can still cross the split, so this is not an independent field test.

**What is the confidence percentage?** The fitted forest's `predict_proba` estimate for its chosen class. It is not a calibrated guarantee that the traffic is malicious. The explanation panel shows feature contributions to that probability along actual decision paths.

**What is the difference between sample mode and real analysis?** Sample mode displays deterministic UI fixtures with illustrative labels. Real mode imports and parses actual PCAP bytes, then uses the installed model for predictions. Database queries, details, alerts, and reports keep the modes separate and mark sample exports.

**Is Live Monitoring truly live capture?** It is a live WebSocket stream of accelerated replay events from an imported PCAP. It does not sniff an interface. Optional Windows interface capture would need Npcap, permissions, and authorization and is not enabled.

**What happens when the model is missing?** PCAP parsing still works, and imported flows are marked unanalyzed. After training, the user can run the model on that saved capture without reuploading it.

**What are the important limitations?** CICFlowMeter/Scapy numerical equivalence has not been proven; evaluation data comes from the same dataset scenarios; the app is localhost only with no login; replay does not preserve true network timing; uploads are bounded; findings need analyst validation.
