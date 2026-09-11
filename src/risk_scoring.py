"""
Hybrid rule-based and ML risk scoring module for Insider Threat Detection.
"""

import pandas as pd
import numpy as np
from src import config

def calculate_after_hours_score(user_features):
    """Calculate after-hours risk points."""
    ratio = user_features.get('after_hours_login_ratio', 0)
    threshold = getattr(config, 'AFTER_HOURS_THRESHOLD', 0.2)
    max_weight = getattr(config, 'RISK_WEIGHTS', {}).get('after_hours_activity', 10)
    
    if ratio > threshold:
        score = (ratio - threshold) / (1 - threshold) * max_weight
        return min(score, max_weight)
    return 0.0

def calculate_weekend_score(user_features):
    """Calculate weekend activity risk points."""
    ratio = user_features.get('weekend_activity_ratio', 0)
    threshold = getattr(config, 'WEEKEND_THRESHOLD', 0.1)
    max_weight = getattr(config, 'RISK_WEIGHTS', {}).get('weekend_activity', 10)
    
    if ratio > threshold:
        score = (ratio - threshold) / (1 - threshold) * max_weight
        return min(score, max_weight)
    return 0.0

def calculate_file_anomaly_score(user_features):
    """Calculate file activity risk points based on deviation."""
    dev = user_features.get('file_access_deviation', 0)
    threshold = getattr(config, 'FILE_DEVIATION_THRESHOLD', 2.0)
    max_weight = getattr(config, 'RISK_WEIGHTS', {}).get('file_anomaly', 20)
    
    if dev > threshold:
        score = min((dev - threshold) * 5, max_weight)
        return score
    return 0.0

def calculate_usb_score(user_features):
    """Calculate USB activity risk points."""
    usb_count = user_features.get('usb_connect_count', 0)
    max_weight = getattr(config, 'RISK_WEIGHTS', {}).get('usb_activity', 15)
    
    if usb_count > 0:
        return min(usb_count * 3, max_weight)
    return 0.0

def calculate_email_score(user_features):
    """Calculate external email + attachment risk points."""
    ext_emails = user_features.get('external_email_count', 0)
    attachments = user_features.get('attachment_size_total', 0)
    max_weight = getattr(config, 'RISK_WEIGHTS', {}).get('email_activity', 15)
    
    score = (ext_emails * 1.5) + (attachments / 1e6) * 0.5
    return min(score, max_weight)

def calculate_web_score(user_features):
    """Calculate suspicious web activity risk points."""
    suspicious_visits = user_features.get('suspicious_web_visits', 0)
    uploads = user_features.get('web_upload_count', 0)
    max_weight = getattr(config, 'RISK_WEIGHTS', {}).get('web_activity', 15)
    
    score = (suspicious_visits * 2) + (uploads * 1.5)
    return min(score, max_weight)

def calculate_deviation_score(user_features):
    """Calculate behavioral deviation points."""
    spike = user_features.get('activity_spike_score', 0)
    max_weight = getattr(config, 'RISK_WEIGHTS', {}).get('behavioral_deviation', 15)
    
    return min(spike * 5, max_weight)

def calculate_rule_score(user_features):
    """Sum all individual scores."""
    components = {
        'after_hours': calculate_after_hours_score(user_features),
        'weekend': calculate_weekend_score(user_features),
        'file_anomaly': calculate_file_anomaly_score(user_features),
        'usb': calculate_usb_score(user_features),
        'email': calculate_email_score(user_features),
        'web': calculate_web_score(user_features),
        'deviation': calculate_deviation_score(user_features)
    }
    return {
        'component_scores': components,
        'total_score': sum(components.values())
    }

def calculate_hybrid_score(rule_score, ml_anomaly_score):
    """Combine rule and ML scores."""
    rule_w = getattr(config, 'RULE_WEIGHT', 0.5)
    ml_w = getattr(config, 'ML_WEIGHT', 0.5)
    
    hybrid = (rule_w * rule_score) + (ml_w * ml_anomaly_score)
    return np.clip(hybrid, 0, 100)

def score_all_users(features_df, anomaly_scores_df):
    """
    Score every user.
    """
    results = []
    
    features = features_df.copy()
    if 'user' in features.columns:
        features = features.set_index('user')
        
    anomaly_map = anomaly_scores_df.set_index('user')['anomaly_score'].to_dict()
    
    classify_fn = getattr(config, 'classify_risk_level', lambda x: 'High' if x > 75 else ('Medium' if x > 50 else 'Low'))
    
    for user, row in features.iterrows():
        rule_results = calculate_rule_score(row.to_dict())
        rule_score = rule_results['total_score']
        ml_score = anomaly_map.get(user, 0.0)
        
        hybrid_score = calculate_hybrid_score(rule_score, ml_score)
        risk_level = classify_fn(hybrid_score)
        
        results.append({
            'user': user,
            'rule_score': rule_score,
            'ml_score': ml_score,
            'hybrid_score': hybrid_score,
            'risk_level': risk_level,
            'component_scores_dict': rule_results['component_scores']
        })
        
    return pd.DataFrame(results)

def generate_risk_report(user_id, score_row, features_row):
    """Generate a formatted text report for a single user."""
    components = score_row.get('component_scores_dict', {})
    
    report = f"Risk Report for User: {user_id}\n"
    report += f"{'='*40}\n"
    report += f"Risk Score: {score_row.get('hybrid_score', 0):.2f}/100\n"
    report += f"Risk Level: {score_row.get('risk_level', 'Unknown')}\n"
    report += f"{'-'*40}\n"
    report += "Evidence List:\n"
    
    for comp, val in components.items():
        if val > 0:
            report += f" [✓] {comp}: Triggered (Score: {val:.2f})\n"
        else:
            report += f" [ ] {comp}: Normal\n"
            
    report += f"{'-'*40}\n"
    report += "Conclusion: "
    if score_row.get('hybrid_score', 0) > 75:
        report += "User exhibits significant high-risk behavior warranting immediate review.\n"
    else:
        report += "User activity is within acceptable or monitored parameters.\n"
        
    return report

def get_top_risk_users(scores_df, n=10):
    """Return top N users by hybrid_score descending."""
    return scores_df.sort_values(by='hybrid_score', ascending=False).head(n)
