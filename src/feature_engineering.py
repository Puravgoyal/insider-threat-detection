"""
Feature Engineering module for Insider Threat Detection project.

This module extracts 15 behavioral features for each user based on
the CERT Insider Threat Dataset.
"""
import pandas as pd
import numpy as np
from src import config

def extract_login_features(logon_df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract per-user login features.
    
    Args:
        logon_df: Logon events DataFrame.
        
    Returns:
        DataFrame indexed by user with login features.
    """
    if logon_df.empty:
        return pd.DataFrame()
        
    df = logon_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df['date']):
        df['date'] = pd.to_datetime(df['date'])
        
    df['hour'] = df['date'].dt.hour
    df['date_only'] = df['date'].dt.date
    if 'is_after_hours' not in df.columns:
        df['is_after_hours'] = (df['hour'] < getattr(config, 'WORK_START_HOUR', 8)) | (df['hour'] >= getattr(config, 'WORK_END_HOUR', 18))
    if 'is_weekend' not in df.columns:
        df['is_weekend'] = df['date'].dt.dayofweek >= 5
    
    df['is_night'] = (df['hour'] >= 0) & (df['hour'] < 5)

    features = df.groupby('user').agg(
        total_logins=('id', 'count'),
        after_hours_logins=('is_after_hours', 'sum'),
        weekend_logins=('is_weekend', 'sum'),
        night_logins=('is_night', 'sum'),
        unique_days=('date_only', 'nunique'),
        unique_pc_count=('pc', 'nunique')
    )
    
    features['after_hours_login_ratio'] = features['after_hours_logins'] / features['total_logins'].replace(0, 1)
    features['weekend_login_ratio'] = features['weekend_logins'] / features['total_logins'].replace(0, 1)
    features['avg_daily_logins'] = features['total_logins'] / features['unique_days'].replace(0, 1)
    features['night_activity_ratio'] = features['night_logins'] / features['total_logins'].replace(0, 1)
    
    return features[['after_hours_login_ratio', 'weekend_login_ratio', 'avg_daily_logins', 'night_activity_ratio', 'unique_pc_count']]


def extract_file_features(file_df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract per-user file activity features.
    
    Args:
        file_df: File events DataFrame.
        
    Returns:
        DataFrame indexed by user with file features.
    """
    if file_df.empty:
        return pd.DataFrame()
        
    df = file_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df['date']):
        df['date'] = pd.to_datetime(df['date'])
        
    df['date_only'] = df['date'].dt.date
    if 'is_sensitive' not in df.columns:
        df['is_sensitive'] = False

    daily_counts = df.groupby(['user', 'date_only']).size().reset_index(name='daily_files')
    user_stats = daily_counts.groupby('user').agg(
        max_daily_files=('daily_files', 'max'),
        avg_daily_files=('daily_files', 'mean')
    )
    
    user_stats['file_access_deviation'] = user_stats['max_daily_files'] / user_stats['avg_daily_files'].replace(0, 1)
    
    features = df.groupby('user').agg(
        total_file_access=('id', 'count'),
        sensitive_file_access=('is_sensitive', 'sum')
    )
    
    features = features.join(user_stats[['file_access_deviation']])
    return features[['total_file_access', 'file_access_deviation', 'sensitive_file_access']]


def extract_email_features(email_df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract per-user email features.
    
    Args:
        email_df: Email events DataFrame.
        
    Returns:
        DataFrame indexed by user with email features.
    """
    if email_df.empty:
        return pd.DataFrame()
        
    df = email_df.copy()
    
    if 'is_external' not in df.columns:
        df['is_external'] = False
    if 'has_attachment' not in df.columns and 'has_attachments' not in df.columns:
        if 'attachments' in df.columns:
            df['has_attachment'] = df['attachments'].notna() & (df['attachments'] != '') & (df['attachments'] != 0)
        else:
            df['has_attachment'] = False
    elif 'has_attachments' in df.columns and 'has_attachment' not in df.columns:
        df['has_attachment'] = df['has_attachments']
        
    df['external_and_attachment'] = df['is_external'] & df['has_attachment']
    
    features = df.groupby('user').agg(
        external_email_count=('is_external', 'sum'),
        email_attachment_count=('has_attachment', 'sum'),
        external_email_with_attachment=('external_and_attachment', 'sum')
    )
    
    return features


def extract_device_features(device_df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract per-user device features.
    
    Args:
        device_df: Device events DataFrame.
        
    Returns:
        DataFrame indexed by user with device features.
    """
    if device_df.empty:
        return pd.DataFrame()
        
    df = device_df.copy()
    
    is_connect = df['activity'].str.lower() == 'connect' if 'activity' in df.columns else pd.Series(True, index=df.index)
    df['is_connect'] = is_connect
    
    features = df.groupby('user').agg(
        usb_connection_count=('is_connect', 'sum')
    )
    
    return features


def extract_web_features(http_df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract per-user web activity features.
    
    Args:
        http_df: Http events DataFrame.
        
    Returns:
        DataFrame indexed by user with web features.
    """
    if http_df.empty:
        return pd.DataFrame()
        
    df = http_df.copy()
    
    if 'is_suspicious' not in df.columns and 'is_suspicious_domain' in df.columns:
        df['is_suspicious'] = df['is_suspicious_domain']
    elif 'is_suspicious' not in df.columns:
        df['is_suspicious'] = False
        
    features = df.groupby('user').agg(
        suspicious_url_count=('is_suspicious', 'sum')
    )
    
    return features


def compute_activity_spike(datasets: dict) -> pd.DataFrame:
    """
    Compute activity_spike_score for each user.
    
    Args:
        datasets: Dict containing all event DataFrames.
        
    Returns:
        DataFrame indexed by user with 'activity_spike_score'.
    """
    all_events = []
    for name, df in datasets.items():
        if not df.empty and 'date' in df.columns and 'user' in df.columns:
            temp = df[['user', 'date']].copy()
            if not pd.api.types.is_datetime64_any_dtype(temp['date']):
                temp['date'] = pd.to_datetime(temp['date'])
            temp['date_only'] = temp['date'].dt.date
            all_events.append(temp)
            
    if not all_events:
        return pd.DataFrame(columns=['activity_spike_score'])
        
    combined = pd.concat(all_events, ignore_index=True)
    
    daily_counts = combined.groupby(['user', 'date_only']).size().reset_index(name='count')
    user_stats = daily_counts.groupby('user').agg(
        max_count=('count', 'max'),
        mean_count=('count', 'mean'),
        std_count=('count', 'std')
    )
    
    # Calculate z-score like metric
    user_stats['std_count'] = user_stats['std_count'].replace(0, 1).fillna(1)
    user_stats['activity_spike_score'] = (user_stats['max_count'] - user_stats['mean_count']) / user_stats['std_count']
    
    return user_stats[['activity_spike_score']]


def compute_usb_file_correlation(device_df: pd.DataFrame, file_df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute correlation between USB connect events and file accesses.
    
    Args:
        device_df: Device events DataFrame.
        file_df: File events DataFrame.
        
    Returns:
        DataFrame indexed by user with 'usb_file_correlation'.
    """
    if device_df.empty or file_df.empty:
        # Get users from whichever is not empty to return 0s, or empty df
        users = pd.concat([device_df['user'] if not device_df.empty else pd.Series(), 
                           file_df['user'] if not file_df.empty else pd.Series()]).unique()
        return pd.DataFrame({'usb_file_correlation': [0.0]*len(users)}, index=users)
        
    dev = device_df.copy()
    fil = file_df.copy()
    
    if not pd.api.types.is_datetime64_any_dtype(dev['date']):
        dev['date'] = pd.to_datetime(dev['date'])
    if not pd.api.types.is_datetime64_any_dtype(fil['date']):
        fil['date'] = pd.to_datetime(fil['date'])
        
    dev = dev[dev['activity'].str.lower() == 'connect'] if 'activity' in dev.columns else dev
    
    correlation_scores = {}
    users = set(dev['user'].unique()).union(set(fil['user'].unique()))
    
    for user in users:
        u_dev = dev[dev['user'] == user].sort_values('date')
        u_fil = fil[fil['user'] == user].sort_values('date')
        
        if u_dev.empty or u_fil.empty:
            correlation_scores[user] = 0.0
            continue
            
        score = 0
        for _, dev_row in u_dev.iterrows():
            connect_time = dev_row['date']
            # Find files accessed within 30 minutes after connect
            mask = (u_fil['date'] >= connect_time) & (u_fil['date'] <= connect_time + pd.Timedelta(minutes=30))
            score += mask.sum()
            
        correlation_scores[user] = float(score)
        
    df = pd.DataFrame.from_dict(correlation_scores, orient='index', columns=['usb_file_correlation'])
    df.index.name = 'user'
    return df


def extract_all_features(datasets: dict) -> pd.DataFrame:
    """
    Master function to extract all features and merge them.
    
    Args:
        datasets: Dict containing all event DataFrames.
        
    Returns:
        Merged feature matrix DataFrame indexed by user.
    """
    features_list = []
    
    if 'logon' in datasets:
        features_list.append(extract_login_features(datasets['logon']))
    if 'file' in datasets:
        features_list.append(extract_file_features(datasets['file']))
    if 'email' in datasets:
        features_list.append(extract_email_features(datasets['email']))
    if 'device' in datasets:
        features_list.append(extract_device_features(datasets['device']))
    if 'http' in datasets:
        features_list.append(extract_web_features(datasets['http']))
        
    features_list.append(compute_activity_spike(datasets))
    
    device_df = datasets.get('device', pd.DataFrame())
    file_df = datasets.get('file', pd.DataFrame())
    features_list.append(compute_usb_file_correlation(device_df, file_df))
    
    # Filter out empty frames
    features_list = [f for f in features_list if not f.empty]
    
    if not features_list:
        return pd.DataFrame()
        
    merged = features_list[0]
    for f in features_list[1:]:
        merged = merged.join(f, how='outer')
        
    # Fill NaN with 0
    merged.fillna(0, inplace=True)
    return merged
