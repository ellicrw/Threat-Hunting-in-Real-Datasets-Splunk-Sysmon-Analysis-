# Threat Hunting in Real Datasets (Splunk – Sysmon Analysis)

## Overview
This project demonstrates a full-scale threat hunting investigation using Windows Sysmon logs in Splunk. The goal was to detect attacker behavior that bypasses traditional alerts, with a focus on **WMI-based lateral movement**, **remote execution**, and **persistence mechanisms**.

The investigation follows a **Tier 2 SOC / Threat Hunting workflow**, combining hypothesis-driven analysis, structured SPL queries, and MITRE ATT&CK mapping to reconstruct a complete attack timeline.

---

## Objectives
- Detect lateral movement across internal systems
- Identify abuse of Windows Management Instrumentation (WMI)
- Uncover persistence mechanisms
- Correlate logs into a structured attack timeline
- Map observed behavior to MITRE ATT&CK

---

## Tools & Technologies
- Splunk (log ingestion, SPL queries)
- Windows Sysmon logs
- CyberDefenders dataset
- MITRE ATT&CK Framework

---

## Dataset Details
- File: `wmi_remote_registry_sysmon.xml`
- Log Source: Microsoft Sysmon Operational Logs
- Host: Berserk / MSEDGEWIN10

### Relevant Event IDs
| Event ID | Description |
|--------|------------|
| 1 | Process Creation |
| 3 | Network Connection |
| 7 | Image Loaded |
| 12 | Registry Key Created |
| 13 | Registry Value Set |

---

## Investigation Methodology

### Hypothesis
The investigation was based on the following assumptions:
- Lateral movement may occur via WMI (RPC port 135)
- Attackers may use legitimate binaries (LOLBins)
- Persistence may be established via registry Run keys

---

## Detection Logic

### Lateral Movement (WMI over RPC)

```spl
source="wmi_remote_registry_sysmon.xml" host="Berserk" sourcetype="VMTX" EventCode=3
| search dest_port=135 OR dest_port=445
| stats count by src_ip, dest_ip, dest_port, user, Image
| where count > 2
| sort - count
