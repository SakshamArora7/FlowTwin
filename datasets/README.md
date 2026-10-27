# Datasets and sample capture

`fetch_cicids2017.py` downloads five flow tables from the [bvsam Parquet mirror](https://huggingface.co/datasets/bvsam/cic-ids-2017) of [UNB/CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html). It records source URLs, byte counts and SHA-256 hashes in `raw/manifest.json`. Downloaded files are ignored by Git. These are labeled flow tables for model training and evaluation, not raw PCAPs.

`generate_sample_pcap.py` creates `sample_capture.pcap`, a nine-packet synthetic capture used only to exercise the parser and reviewer walkthrough. It has no ground-truth malicious label. Demo mode in the app uses separate deterministic fixture rows from `backend/app/demo.py`; neither source is used to claim classifier accuracy.

Use only captures you are authorized to analyze. The training and walkthrough commands are in the [project README](../README.md).
