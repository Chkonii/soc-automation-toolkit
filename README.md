# SOC Automation Toolkit

A modular collection of Python-based Security Operations Center (SOC) tools designed for log analysis, threat detection, and automated SIEM ingestion. 

This repository utilizes a flat-monorepo architecture, separating distinct security utilities into standalone pipelines that can be daisy-chained together for enterprise-scale log processing.

### 1. [SSH Analysis & Report Generator](./ssh_analysis_report)
A dual-engine (Standard Python & Pandas) log analyzer that detects persistent SSH brute-force campaigns and high-frequency burst attacks. It operates as an edge-analytics processor, routing actionable intelligence into Text, PDF, or SIEM-ready JSON formats.

### 2. [Log Generator](./log_generator)
A utility script used to generate simulated, highly realistic SSH authentication logs with embedded attack patterns (bursts, distributed attacks) for safe lab testing and pipeline validation.

---

**Completed Milestones**
- [x] Add CLI interface with `argparse` for flexible, automated pipeline execution.
- [x] Add JSON payload routing for seamless SIEM (Splunk/Elastic) ingestion.
- [x] Refactor core analyzer with `pandas` for large-scale, heavy log processing.
- [x] Implement dynamic management reporting (PDF generation).

**Upcoming Toolkit Additions**
- [ ] Splunk HEC Shipper
- [ ] Real-Time Analyzer
- [ ] Private IDR (Incident Detection & Response)
- [ ] Attack Simulator
- [ ] Threat Intelligence Platform (TIP)
- [ ] Honeypots
- [ ] Triage Bot
- [ ] Network Blocker
- [ ] Identity Lock
- [ ] Data Lake / Cold Storage

---

## Author
**Giorgi Chkonia** — MS Computer Science, Brooklyn College  
*Focused on the intersection of Cybersecurity, Computer Science, and Systems Automation.*
