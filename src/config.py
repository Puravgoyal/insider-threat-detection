"""
config.py - Project Configuration
==================================
Central configuration for the Insider Threat Detection project.
Contains file paths, working-hour definitions, risk-score weights,
suspicious domain categories, and risk-level thresholds.
"""

import os
from pathlib import Path

# ──────────────────────────────────────────────
# Project Paths
# ──────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_RAW_DIR = PROJECT_ROOT / "data" / "raw"
DATA_PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
OUTPUT_DIR = PROJECT_ROOT / "output"
FIGURES_DIR = OUTPUT_DIR / "figures"
REPORTS_DIR = OUTPUT_DIR / "reports"

# Ensure output directories exist
for d in [DATA_PROCESSED_DIR, FIGURES_DIR, REPORTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ──────────────────────────────────────────────
# Expected Dataset Files
# ──────────────────────────────────────────────
DATASET_FILES = {
    "logon":  DATA_RAW_DIR / "logon.csv",
    "file":   DATA_RAW_DIR / "file.csv",
    "email":  DATA_RAW_DIR / "email.csv",
    "http":   DATA_RAW_DIR / "http.csv",
    "device": DATA_RAW_DIR / "device.csv",
}

# ──────────────────────────────────────────────
# Working Hours Definition
# ──────────────────────────────────────────────
WORK_HOUR_START = 7   # 7:00 AM
WORK_HOUR_END   = 19  # 7:00 PM (19:00)

# Night hours (midnight - 5 AM) — extra suspicious
NIGHT_HOUR_START = 0
NIGHT_HOUR_END   = 5

# ──────────────────────────────────────────────
# Risk Score Weights (Rule-Based)
# ──────────────────────────────────────────────
# Each indicator contributes a maximum number of points
# Total maximum = 100
RISK_WEIGHTS = {
    "after_hours_activity":     10,
    "weekend_activity":         10,
    "abnormal_file_activity":   20,
    "usb_activity":             20,
    "external_email_attachment": 15,
    "suspicious_web_activity":  10,
    "behavioral_deviation":     15,
}

# ──────────────────────────────────────────────
# Hybrid Scoring Weights
# ──────────────────────────────────────────────
RULE_WEIGHT = 0.6   # Weight for rule-based score
ML_WEIGHT   = 0.4   # Weight for ML anomaly score

# ──────────────────────────────────────────────
# Risk Level Thresholds
# ──────────────────────────────────────────────
RISK_LEVELS = {
    "LOW":      (0,  30),
    "MEDIUM":   (31, 60),
    "HIGH":     (61, 80),
    "CRITICAL": (81, 100),
}

def classify_risk_level(score: float) -> str:
    """Classify a numeric risk score (0-100) into a risk level."""
    score = max(0, min(100, score))
    for level, (low, high) in RISK_LEVELS.items():
        if low <= score <= high:
            return level
    return "CRITICAL"

# ──────────────────────────────────────────────
# Suspicious Domain / URL Categories
# ──────────────────────────────────────────────
SUSPICIOUS_DOMAINS = {
    "cloud_storage": [
        "dropbox.com", "drive.google.com", "onedrive.live.com",
        "box.com", "icloud.com", "mega.nz", "mediafire.com",
        "pcloud.com", "sync.com",
    ],
    "file_sharing": [
        "wetransfer.com", "sendspace.com", "filedropper.com",
        "file.io", "transfer.sh", "gofile.io", "zippyshare.com",
        "rapidshare.com", "4shared.com",
    ],
    "personal_email": [
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "protonmail.com", "mail.com", "aol.com", "zoho.com",
        "yandex.com", "tutanota.com",
    ],
    "job_search": [
        "linkedin.com", "indeed.com", "glassdoor.com",
        "monster.com", "careerbuilder.com",
    ],
}

# Flatten into a single set for quick lookup
ALL_SUSPICIOUS_DOMAINS = set()
for domains in SUSPICIOUS_DOMAINS.values():
    ALL_SUSPICIOUS_DOMAINS.update(domains)

# ──────────────────────────────────────────────
# Sensitive File Extensions
# ──────────────────────────────────────────────
SENSITIVE_FILE_EXTENSIONS = {
    ".docx", ".xlsx", ".pptx", ".pdf", ".csv",
    ".sql", ".db", ".mdb", ".accdb",
    ".pem", ".key", ".cer", ".pfx",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".conf", ".cfg", ".ini", ".env",
}

# ──────────────────────────────────────────────
# Anomaly Detection Parameters
# ──────────────────────────────────────────────
ISOLATION_FOREST_PARAMS = {
    "n_estimators":  100,
    "contamination": 0.05,   # Expect ~5% anomalous users
    "random_state":  42,
    "max_samples":   "auto",
}

# ──────────────────────────────────────────────
# Feature Deviation Thresholds
# ──────────────────────────────────────────────
FILE_DEVIATION_THRESHOLD   = 3.0   # 3× normal = suspicious
AFTER_HOURS_THRESHOLD      = 0.15  # >15% after-hours = suspicious
WEEKEND_THRESHOLD          = 0.10  # >10% weekend activity = suspicious
EMAIL_DEVIATION_THRESHOLD  = 3.0   # 3× normal external emails

# ──────────────────────────────────────────────
# Visualization Settings
# ──────────────────────────────────────────────
FIGURE_DPI = 150
FIGURE_STYLE = "seaborn-v0_8-darkgrid"
COLOR_PALETTE = "coolwarm"

# Color scheme for risk levels
RISK_COLORS = {
    "LOW":      "#2ecc71",  # Green
    "MEDIUM":   "#f39c12",  # Orange
    "HIGH":     "#e74c3c",  # Red
    "CRITICAL": "#8e44ad",  # Purple
}
