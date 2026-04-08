# SSH Brute Force Detector

A Python tool that generates realistic SSH authentication logs and analyzes them to detect brute force attacks, suspicious IPs, targeted user accounts, and burst attack patterns.

## About

This project simulates what a junior SOC analyst or sysadmin would do when reviewing SSH auth logs — identify who is attacking, what accounts they're targeting, and whether the attacks are automated. It includes a log generator for testing and an analyzer that produces a security report.

## Files

- `log_generation.py` — Generates simulated SSH auth logs with realistic attack patterns including burst attacks
- `analyzer.py` — Parses logs, flags suspicious activity, and writes a detection report
- `Report.txt` — Sample report output from the analyzer
- `Auth_log_Advanced.csv` — Sample generated log file

## How To Run

1. Clone the repository:


2. Generate logs: 
python3 log_generation.py

3. Run the Analyzer:
python3 analyzer.py

4. View the Report:
cat Report.txt


## What it detects

- IPs with 5 or more failed login attempts
- User accounts with 3 or more failed login attempts
- Burst attacks: 4 or more failures from the same IP within a 10-second window

## Configuration

Detection thresholds can be adjusted at the start of "analyzer.py"

FAILED_IP_THRESHOLD = 5
FAILED_USER_THRESHOLD = 3
BURST_WINDOW = 10
BURST_THRESHOLD = 4


## Sample Output

SOC analysis report
Report generated 2026-04-08 14:03:48
Log file analyzed: Auth_log_advanced.csv
Total failed attempts: 91
--------------------------------------------------

Critical 5 or more failed ips: 45.33.22.11 - 9
Critical 5 or more failed ips: 114.119.160.20 - 13
Critical 5 or more failed ips: 193.188.22.11 - 12
Critical 5 or more failed ips: 92.118.38.55 - 5
Critical 5 or more failed ips: 201.11.9.88 - 14
Critical 5 or more failed ips: 178.62.10.11 - 7
Critical 5 or more failed ips: 103.45.67.89 - 12
Critical 5 or more failed ips: 185.22.33.44 - 16
ALERT: postgres - 19 failed attempts
ALERT: ubuntu - 27 failed attempts
ALERT: admin - 22 failed attempts
ALERT: root - 16 failed attempts
ALERT: testuser - 4 failed attempts
ALERT: webmaster - 3 failed attempts
BURST: 45.33.22.11 had 5 failures within 10s starting at 15:47:48
BURST: 114.119.160.20 had 5 failures within 10s starting at 15:48:34
BURST: 193.188.22.11 had 4 failures within 10s starting at 15:55:12
BURST: 201.11.9.88 had 5 failures within 10s starting at 16:01:43
BURST: 178.62.10.11 had 5 failures within 10s starting at 15:59:00
BURST: 103.45.67.89 had 4 failures within 10s starting at 16:05:14
BURST: 185.22.33.44 had 4 failures within 10s starting at 15:58:21



## Roadmap

- [ ] Add CLI interface with argparse for flexible input/output options
- [ ] Add JSON log format support alongside CSV
- [ ] Refactor analyzer with Pandas for large-scale log processing
- [ ] Add threat intelligence enrichment (IP geolocation and known threat actor mapping)
- [ ] Deploy against live honeypot traffic on a real VPS

## Built With

- Python 3
- Standard library only (csv, datetime, random)

## Author

Giorgi Chkonia — MS Computer Science, Brooklyn College
