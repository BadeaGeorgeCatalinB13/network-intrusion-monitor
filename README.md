# network-intrusion-monitor

A Raspberry Pi 5 network drop box that watches a local LAN for unknown devices and reports them over Telegram, plus an optional machine-learning add-on (`P2/`) that flags anomalous traffic patterns using an Isolation Forest model.

## How it works

**Drop box (`dropbox.py`)**
- Runs an nmap ping-sweep of the local subnet every 5 minutes.
- Diffs the MAC addresses found against a whitelist stored in `dispozitive_cunoscute.json` (auto-generated on first run).
- On a new, unrecognized MAC: sends a Telegram alert, runs a detailed nmap port/service scan (`-F -sV`) against that host, sends a second Telegram message with the port report, and adds the device to the whitelist.

**Anomaly detector (`P2/`)** — a separate 3-stage ML pipeline for traffic-based intrusion detection:
1. `colectare.py` — captures live traffic with `scapy` and writes aggregated per-window features (packet count, byte count, unique IPs/ports, TCP/UDP ratio) to `trafic_normal.csv`.
2. `antrenare.py` — trains a scikit-learn `IsolationForest` on that baseline traffic and saves `model_anomalii.joblib`.
3. `detectie.py` — runs the trained model against live traffic and prints an alert to the terminal when a window is scored as anomalous.

The two components are independent and can be run separately.

`P2/trafic_normal.csv` (the training data) and `model_anomalii.joblib` (the trained model) are generated artifacts and are not stored in this repo — run `colectare.py` (and then `antrenare.py`) locally to produce them.

## Requirements

- Raspberry Pi 5 (or any Linux host) with `nmap` installed at the OS level.
- Python 3.13+
- Python packages: `python-nmap`, `requests` (drop box); `scapy`, `pandas`, `scikit-learn`, `joblib` (anomaly detector). See `requirements.txt`.
- A Telegram bot (via [@BotFather](https://t.me/BotFather)) and the chat ID to receive alerts in.

## Setup

1. Install system dependencies:
   ```bash
   sudo apt update
   sudo apt install nmap
   ```
2. Create a virtual environment and install Python dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Configure the Telegram credentials as environment variables — never hardcode them. Copy `.env.example` to `.env` and fill in real values:
   ```bash
   cp .env.example .env
   ```
   `dropbox.py` reads `TOKEN_TELEGRAM`, `CHAT_ID`, and optionally `SUBNET_RETEA` (defaults to `192.168.1.0/24`) from the environment. Export them before running, e.g.:
   ```bash
   export $(grep -v '^#' .env | xargs)
   ```
4. `dispozitive_cunoscute.json` is the device whitelist; it is created automatically on first run and updated as new devices are approved. The copy in this repo contains fictional example entries and should be deleted before first real use.

## Usage

Run the drop box (needs root for nmap's raw scans):
```bash
sudo -E python3 dropbox.py
```

Run the anomaly detector pipeline from `P2/`, in order:
```bash
sudo python3 P2/colectare.py   # capture a baseline of normal traffic -> trafic_normal.csv
python3 P2/antrenare.py        # train the Isolation Forest -> model_anomalii.joblib
sudo python3 P2/detectie.py    # live detection against the trained model
```

To run the drop box as a systemd service, point `ExecStart`/`WorkingDirectory` at your install path and load `.env` via `EnvironmentFile=` in the unit file.
