# Wireless Network Attack Detector

A Python/Tkinter defensive monitoring project for a cybersecurity networking course. It inspects captured packets and raises alerts for suspicious patterns.

## Features

- Deauthentication-frame activity monitoring (wireless capture support required)
- ARP IP-to-MAC changes
- TCP SYN packets across multiple destination ports
- High TCP SYN volume from one source
- Tkinter dashboard, severity counters, and CSV alert log
- Offline synthetic-packet demonstration that does not transmit traffic

> **Limitations:** These are simple heuristic indicators, not proof that an attack occurred. Legitimate network changes or high traffic can cause false positives. Deauthentication detection requires a compatible wireless adapter and suitable capture mode. Capture permissions and supported interfaces depend on your operating system.

## Requirements

- Python 3.10 or newer recommended
- Scapy
- Tkinter (often installed separately on Linux)

Install Scapy:

```bash
python -m pip install -r requirements.txt
```

On Debian/Kali Linux, if Tkinter is missing:

```bash
sudo apt install python3-tk
```

## Run the application

```bash
python detector.py
```

Select an interface and click **Start Detection**. Packet capture may require administrator/root privileges depending on your operating system. Only monitor networks and devices you are authorized to assess.

## Run the safe offline demonstration

```bash
python simulate_attacks.py
```

This script builds synthetic Scapy packets in memory and passes them to the detection rules. It does **not** call `send`, `sendp`, or transmit traffic over a network. This is the recommended way to demonstrate the detection logic in a portfolio or class presentation.

## Files

```text
Wireless-Network-Attack-Detector/
├── detector.py          # Tkinter UI and packet capture lifecycle
├── detection.py         # Detection rules and state
├── alert_logger.py      # CSV alert logging
├── simulate_attacks.py  # Offline synthetic test harness only
├── requirements.txt
├── .gitignore
└── README.md
```

## Logs and privacy

The application creates `alerts_log.csv` when it runs. The file is ignored by Git because real monitoring logs may contain network identifiers. Do not commit real traffic captures, private IP/MAC inventories, or personal information. If you want to include sample output in a report, use sanitized fictional data.

## Known simplifications

- Detection thresholds are basic and intended for educational demonstration.
- Port-scan tracking is not time-windowed, so long-running captures may accumulate destination ports.
- SYN-volume tracking is cumulative per source for the session; it is not a rate-based detector.
- The app is a learning prototype, not a production IDS.
