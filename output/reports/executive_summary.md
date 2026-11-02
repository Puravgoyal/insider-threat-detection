# Forensic Investigation Executive Summary
**Project:** Insider Threat Detection Through Forensic Analysis of User Activity Logs  
**Status:** Completed Analysis  

## Summary of Findings
- **Total Users Evaluated:** 1000
- **Flagged / Monitored Users:** 450
- **Top Suspicious User:** AJF0370 (Risk Score: 46.32)

## Top 5 Suspicious Users
| User ID | Rule-Based Score | ML Anomaly Score | Hybrid Risk Score | Risk Level |
|---------|------------------|------------------|-------------------|------------|
| AJF0370 | 34.34 | 64.29 | 46.32 | MEDIUM |
| IBB0359 | 36.13 | 60.65 | 45.94 | MEDIUM |
| EIS0041 | 35.61 | 59.07 | 45.00 | MEDIUM |
| MPM0220 | 34.48 | 60.72 | 44.98 | MEDIUM |
| HDS0367 | 35.82 | 58.40 | 44.85 | MEDIUM |

## Key Threat Indicators Identified
1. **Unusual After-Hours Logins:** Spikes in access between 7:00 PM and 6:00 AM.
2. **Abnormal USB Device Activity:** Removable media insertion events closely coupled with file operations.
3. **Data Exfiltration Vectors:** High volume of sensitive file transfers and external email communications.

## Generated Forensic Artifacts
- **Risk Scores:** `output/risk_scores.csv`
- **Visual Evidence:** `output/figures/`
- **Individual User Forensic Reports:** `output/reports/`
