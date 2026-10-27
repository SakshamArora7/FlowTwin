# Machine learning

`schema.py` is the ordered seven-feature contract shared by training and PCAP inference. `train.py` reads selected CIC-IDS2017 Parquet files, cleans and splits rows, trains a median-imputed Random Forest, and writes a Joblib artifact and JSON evaluation to the ignored `ml/artifacts/` directory. Run it from the project root as documented in [README](../README.md).

The current local artifact was trained on 50,117 rows and scored on 12,324 later, distinct rows from the same source files. Its weighted F1 is 0.9484. This holdout does not measure performance on unseen capture days or networks. CICFlowMeter generated the source features; exact equivalence to this app's Scapy extractor has not been established. See [evaluation and caveats](../docs/phases-2-to-4.md).
