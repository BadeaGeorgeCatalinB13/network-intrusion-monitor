# Anomaly Detector (P2)

A 3-stage, ML-based network traffic anomaly detector using an Isolation
Forest model. Independent of the drop box (`dropbox.py`) in the repo root.

## How it works

1. `colectare.py` — captures live traffic with `scapy` on `wlan0`, over 30
   windows of 10 seconds each, and writes aggregated per-window features
   (packet count, byte count, unique IPs/ports, TCP/UDP ratio) to
   `trafic_normal.csv`.
2. `antrenare.py` — trains a scikit-learn `IsolationForest`
   (`contamination=0.05`) on `trafic_normal.csv` and saves the model to
   `model_anomalii.joblib`.
3. `detectie.py` — loads the trained model and scores live traffic the same
   way, printing an alert to the terminal for any window flagged anomalous.

## Requirements

- Python 3.13+
- Packages: `scapy`, `pandas`, `scikit-learn`, `joblib` (see the repo-level
  `requirements.txt`).

## Usage

Run from the repo root, in order:

```bash
sudo python3 P2/colectare.py   # capture a baseline of normal traffic -> trafic_normal.csv
python3 P2/antrenare.py        # train the Isolation Forest -> model_anomalii.joblib
sudo python3 P2/detectie.py    # live detection against the trained model
```

`trafic_normal.csv` and `model_anomalii.joblib` are generated artifacts and
are not checked into the repo (see `.gitignore`).
