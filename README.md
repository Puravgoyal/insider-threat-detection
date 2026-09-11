# Insider Threat Detection Using Behavioral and Forensic Analysis of Enterprise Activity Logs

## Overview

This project performs **forensic analysis of enterprise user activity logs** to identify potential insider threats. It implements a **hybrid detection approach** combining rule-based forensic analysis with machine learning (Isolation Forest) anomaly detection.

### Central Research Question

> *"Can behavioral patterns extracted from enterprise activity logs be used to identify anomalous user activity indicative of potential insider threats?"*

### Sub-Questions

- **RQ1:** What does normal employee behavior look like?
- **RQ2:** What behavioral changes are associated with known malicious users?
- **RQ3:** Which activity features are strongest indicators of insider threats?
- **RQ4:** Can users be assigned a forensic risk score based on these indicators?

---

## Dataset

This project uses the **CERT Insider Threat Dataset** from Carnegie Mellon University's Software Engineering Institute.

**Download:** [CMU Figshare Repository](https://doi.org/10.1184/R1/12841247.v1)

Recommended version: **r4.2** or **r5.2**

### Required Files

Place the following CSV files in `data/raw/`:

| File | Description |
|------|-------------|
| `logon.csv` | User login/logout events |
| `file.csv` | File access operations |
| `email.csv` | Email activity |
| `http.csv` | Web browsing activity |
| `device.csv` | USB/removable device events |

---

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Place Dataset

Download the CERT dataset and extract the CSV files into `data/raw/`.

### 3. Run the Analysis

Open and run the main notebook:

```bash
jupyter notebook notebooks/insider_threat_analysis.ipynb
```

---

## Project Structure

```
insider-threat-project/
├── data/
│   ├── raw/                    # Place CERT CSV files here
│   └── processed/              # Cleaned data (auto-generated)
├── src/
│   ├── __init__.py
│   ├── config.py               # Project constants & paths
│   ├── data_loader.py          # Load and inspect raw CSVs
│   ├── preprocessing.py        # Data cleaning & normalization
│   ├── baseline_profiling.py   # Normal behavior profiles
│   ├── feature_engineering.py  # Behavioral feature extraction
│   ├── anomaly_detection.py    # Isolation Forest implementation
│   ├── risk_scoring.py         # Hybrid rule + ML scoring
│   ├── forensic_investigation.py  # Timeline reconstruction
│   └── visualizations.py       # All forensic visualizations
├── notebooks/
│   └── insider_threat_analysis.ipynb   # Main walkthrough
├── output/
│   ├── figures/                # Saved visualization PNGs
│   ├── reports/                # Generated forensic reports
│   └── risk_scores.csv         # Final risk score table
├── requirements.txt
└── README.md
```

---

## Methodology Pipeline

```
CERT Dataset → Data Cleaning → Behavioral Profiling → Feature Engineering
    → Statistical/Rule-Based Analysis → Isolation Forest
    → Hybrid Risk Scoring → Forensic Timeline Reconstruction
```

### Detection Approach

| Component | Description |
|-----------|-------------|
| **Rule-Based Analysis** | Weighted scoring of forensic indicators (after-hours activity, USB usage, file anomalies, etc.) |
| **ML Anomaly Detection** | Isolation Forest trained on 15 behavioral features |
| **Hybrid Score** | Combined: 60% rule-based + 40% ML anomaly score |
| **Forensic Investigation** | Timeline reconstruction and evidence chain analysis for top-risk users |

### Risk Levels

| Score | Level |
|-------|-------|
| 0–30  | LOW |
| 31–60 | MEDIUM |
| 61–80 | HIGH |
| 81–100 | CRITICAL |

---

## Key Features Analyzed

1. After-hours login ratio
2. Weekend login ratio
3. File access deviation (spike detection)
4. USB connection frequency
5. USB-file temporal correlation
6. External email with attachments
7. Suspicious website visits
8. Night activity ratio
9. Unique PC usage (lateral movement)
10. Behavioral deviation score

---

## Technologies

- **Python 3.8+**
- **pandas** — Data manipulation
- **numpy** — Numerical computing
- **matplotlib / seaborn** — Visualizations
- **scikit-learn** — Isolation Forest
- **plotly** — Interactive visualizations
- **Jupyter Notebook** — Analysis walkthrough

---

## License

This project is for academic/educational purposes. The CERT Insider Threat Dataset is provided by CMU SEI under their terms of use.
