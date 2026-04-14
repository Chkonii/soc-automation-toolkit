A modular log analysis utility designed to parse SSH authentication logs, detect persistent brute-force campaigns, and identify high-frequency burst attacks.

This tool serves as an edge-analytics processor, taking raw, noisy log data and outputting clean, actionable intelligence for Incident Response teams and SIEM ingestion.

## Core Features
* **Dual Processing Engines:** Choose between standard Python data structures for lightweight environments, or the Pandas engine for heavy, enterprise-scale datasets.
* **Burst Detection:** Customizable sliding-time-window analysis to catch aggressive, rapid-fire attacks that evade standard threshold limits.
* **Multi-Format Routing:** Outputs data in Standard Text (local logging), PDF (management reporting), or structured JSON (automated SIEM/HEC ingestion).

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ip-threshold` | int | 5 | Failed attempts required to flag an attacking IP. |
| `--user-threshold` | int | 3 | Failed attempts required to flag a targeted user account. |
| `--burst-threshold` | int | 4 | Failures required within the time window to flag a burst attack. |
| `--burst-window` | int | 10 | The sliding time window (in seconds) for burst detection. |
| `--analyzer` | string | python | Engine to run: `python` or `pandas`. |
| `--format` | string | text | Output format: `text`, `json`, or `pdf`. |


## Prerequisites
If using the Pandas engine or generating PDF reports, ensure the required libraries are installed:
```bash
pip install pandas fpdf