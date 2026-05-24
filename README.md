# KEEG — Kinetic Entropy Execution Gating

KEEG is a runtime behavioral cybersecurity framework that detects malicious activity using entropy kinetics and behavioral analysis instead of traditional malware signatures.

It continuously monitors running processes, tracks entropy phase-shifts (EPSD), analyzes process lineage, detects RWX executable memory regions, and correlates multiple runtime threat signals to identify suspicious activity in real time.

## Features

- Shannon entropy analysis
- EPSD (Entropy Phase-Shift Detection)
- Sliding-window entropy scanning
- Process lineage anomaly detection
- RWX memory detection
- Compound threat correlation
- SOC-style monitoring dashboard
- JSON / CSV / SIEM-compatible reports
- Threat simulation engine

## Technologies

- Python 3
- Flask
- psutil
- Chart.js

## Installation

```bash
pip install -r requirements.txt
```

## Run

```bash
python3 keeg_v3.1.py --monitor --dashboard
```

Open:

```text
http://localhost:5000
```

## Demo Mode

```bash
python3 keeg_v3.1.py --demo
```

## Simulation Mode

```bash
python3 keeg_v3.1.py --simulate
```

## Project Type

MCA Final Year Project — Cybersecurity Domain

## License

MIT License
