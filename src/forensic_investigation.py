"""
Forensic investigation module for reconstruction and evidence chains.
"""

import pandas as pd
import numpy as np

def reconstruct_timeline(user_id, datasets):
    """
    Extract all events for a user and combine into a single chronological DataFrame.
    """
    events = []
    
    for source, df in datasets.items():
        if df.empty or 'user' not in df.columns or 'date' not in df.columns:
            continue
            
        user_df = df[df['user'] == user_id].copy()
        if user_df.empty:
            continue
            
        user_df['date'] = pd.to_datetime(user_df['date'], errors='coerce')
        user_df = user_df.dropna(subset=['date'])
        
        for _, row in user_df.iterrows():
            details = row.drop(['user', 'date']).to_dict()
            events.append({
                'timestamp': row['date'],
                'event_type': source,
                'description': f"{source} event",
                'details': str(details)
            })
            
    timeline_df = pd.DataFrame(events)
    if not timeline_df.empty:
        timeline_df = timeline_df.sort_values(by='timestamp').reset_index(drop=True)
    else:
        timeline_df = pd.DataFrame(columns=['timestamp', 'event_type', 'description', 'details'])
        
    return timeline_df

def identify_suspicious_windows(timeline_df, window_hours=2):
    """
    Scan timeline for windows of unusually high activity.
    """
    if timeline_df.empty:
        return []
        
    timeline_df = timeline_df.set_index('timestamp')
    resampled = timeline_df.resample(f'{window_hours}H').size()
    
    mean_count = resampled.mean()
    std_count = resampled.std()
    threshold = mean_count + (2 * std_count)
    
    windows = []
    for ts, count in resampled.items():
        if count > threshold and count > 10:  # arbitrary min count 10
            end_time = ts + pd.Timedelta(hours=window_hours)
            events_in_window = timeline_df[(timeline_df.index >= ts) & (timeline_df.index < end_time)]
            windows.append((ts, end_time, count, events_in_window.reset_index().to_dict('records')))
            
    return windows

def detect_exfiltration_pattern(timeline_df):
    """
    Look for USB connect -> file access -> email -> USB disconnect.
    """
    patterns = []
    if timeline_df.empty:
        return patterns
        
    usb_connect = None
    file_spikes = []
    emails = []
    
    for i, row in timeline_df.iterrows():
        details = row['details']
        if row['event_type'] == 'device' and 'Connect' in details:
            usb_connect = row
            file_spikes = []
            emails = []
        elif row['event_type'] == 'file' and usb_connect is not None:
            file_spikes.append(row)
        elif row['event_type'] == 'email' and usb_connect is not None:
            emails.append(row)
        elif row['event_type'] == 'device' and 'Disconnect' in details and usb_connect is not None:
            if len(file_spikes) > 0 and len(emails) > 0:
                patterns.append({
                    'start_time': usb_connect['timestamp'],
                    'end_time': row['timestamp'],
                    'evidence': {
                        'usb_connect': usb_connect.to_dict(),
                        'file_accesses': len(file_spikes),
                        'emails': len(emails),
                        'usb_disconnect': row.to_dict()
                    }
                })
            usb_connect = None
            
    return patterns

def build_evidence_chain(user_id, features_row, timeline_df):
    """
    Build structured evidence chain.
    """
    chain = []
    ev_num = 1
    
    if features_row.get('after_hours_login_ratio', 0) > 0.2:
        chain.append({
            'evidence_number': ev_num,
            'indicator_type': 'after_hours',
            'description': 'High ratio of after hours logins.',
            'timestamp': 'Multiple',
            'severity': 'Medium'
        })
        ev_num += 1
        
    if features_row.get('usb_connect_count', 0) > 0:
        chain.append({
            'evidence_number': ev_num,
            'indicator_type': 'usb_activity',
            'description': 'USB device connections detected.',
            'timestamp': 'Multiple',
            'severity': 'High'
        })
        ev_num += 1
        
    patterns = detect_exfiltration_pattern(timeline_df)
    for p in patterns:
        chain.append({
            'evidence_number': ev_num,
            'indicator_type': 'exfiltration_pattern',
            'description': 'Possible data exfiltration sequence detected.',
            'timestamp': f"{p['start_time']} to {p['end_time']}",
            'severity': 'Critical'
        })
        ev_num += 1
        
    return chain

def calculate_temporal_relationships(evidence_chain):
    """
    Calculate time deltas for consecutive evidence items if applicable.
    """
    rels = []
    # Simplified version, since some timestamps are "Multiple"
    for i in range(len(evidence_chain)-1):
        ev1 = evidence_chain[i]
        ev2 = evidence_chain[i+1]
        rels.append(f"Evidence {ev1['evidence_number']} -> {ev2['evidence_number']}: Temporal linkage unquantified due to aggregate timestamps.")
    return rels

def generate_forensic_report(user_id, evidence_chain, temporal_rels, risk_score):
    """
    Generate comprehensive formatted text report.
    """
    report = f"Forensic Investigation Report\n"
    report += f"User ID: {user_id}\n"
    report += f"Assessed Risk Score: {risk_score:.2f}\n"
    report += f"{'-'*50}\n"
    
    report += "Evidence Chain:\n"
    for ev in evidence_chain:
        report += f" {ev['evidence_number']}. [{ev['severity']}] {ev['indicator_type']}: {ev['description']} (Time: {ev['timestamp']})\n"
        
    report += f"\nTemporal Relationships:\n"
    for tr in temporal_rels:
        report += f" - {tr}\n"
        
    report += f"\nConclusion:\n"
    report += "User exhibited multiple behavioral anomalies consistent with potential policy violation or data exfiltration. Further manual investigation is advised."
    
    return report

def investigate_top_users(scores_df, features_df, datasets, n=3):
    """
    Run full forensic investigation for top N risk-scored users.
    """
    top_users = scores_df.sort_values(by='hybrid_score', ascending=False).head(n)
    
    reports = {}
    
    features = features_df.copy()
    if 'user' in features.columns:
        features = features.set_index('user')
        
    for _, row in top_users.iterrows():
        user = row['user']
        risk = row['hybrid_score']
        
        f_row = features.loc[user].to_dict() if user in features.index else {}
        
        timeline = reconstruct_timeline(user, datasets)
        chain = build_evidence_chain(user, f_row, timeline)
        rels = calculate_temporal_relationships(chain)
        
        report = generate_forensic_report(user, chain, rels, risk)
        reports[user] = report
        
    return reports
