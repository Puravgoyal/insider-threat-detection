"""
Baseline Profiling module for Insider Threat Detection project.

This module establishes "normal behavior" baselines for each user based on
the CERT Insider Threat Dataset.
"""
import pandas as pd
import numpy as np
from src import config

def build_login_profile(logon_df: pd.DataFrame) -> pd.DataFrame:
    """
    Build user login profiles.
    
    Args:
        logon_df: DataFrame containing logon events.
        
    Returns:
        DataFrame indexed by user with login profile metrics.
    """
    if logon_df.empty:
        return pd.DataFrame()
        
    # Ensure date is datetime
    df = logon_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df['date']):
        df['date'] = pd.to_datetime(df['date'])
        
    df['hour'] = df['date'].dt.hour
    df['date_only'] = df['date'].dt.date
    if 'is_after_hours' not in df.columns:
        df['is_after_hours'] = (df['hour'] < getattr(config, 'WORK_START_HOUR', 8)) | (df['hour'] >= getattr(config, 'WORK_END_HOUR', 18))
    if 'is_weekend' not in df.columns:
        df['is_weekend'] = df['date'].dt.dayofweek >= 5

    def get_most_common(x):
        return x.mode().iloc[0] if not x.empty else np.nan

    profile = df.groupby('user').agg(
        avg_login_hour=('hour', 'mean'),
        total_logins=('id', 'count'),
        after_hours_logins=('is_after_hours', 'sum'),
        weekend_logins=('is_weekend', 'sum'),
        most_common_pc=('pc', get_most_common),
        unique_days=('date_only', 'nunique')
    )
    
    profile['avg_logins_per_day'] = profile['total_logins'] / profile['unique_days'].replace(0, 1)
    profile['after_hours_login_pct'] = profile['after_hours_logins'] / profile['total_logins'].replace(0, 1)
    profile['weekend_login_pct'] = profile['weekend_logins'] / profile['total_logins'].replace(0, 1)
    
    profile.drop(columns=['after_hours_logins', 'weekend_logins', 'unique_days'], inplace=True)
    return profile

def build_file_profile(file_df: pd.DataFrame) -> pd.DataFrame:
    """
    Build user file activity profiles.
    
    Args:
        file_df: DataFrame containing file events.
        
    Returns:
        DataFrame indexed by user with file profile metrics.
    """
    if file_df.empty:
        return pd.DataFrame()
        
    df = file_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df['date']):
        df['date'] = pd.to_datetime(df['date'])
    
    df['date_only'] = df['date'].dt.date
    is_write = df['activity'].str.lower().isin(['file write', 'file copy', 'write', 'copy', 'modify']) if 'activity' in df.columns else False
    
    df['is_write'] = is_write
    if 'is_sensitive' not in df.columns:
        df['is_sensitive'] = False
        
    profile = df.groupby('user').agg(
        total_files=('id', 'count'),
        unique_days=('date_only', 'nunique'),
        write_files=('is_write', 'sum'),
        unique_files_accessed=('filename', 'nunique') if 'filename' in df.columns else ('id', 'nunique'),
        sensitive_files=('is_sensitive', 'sum')
    )
    
    profile['avg_files_per_day'] = profile['total_files'] / profile['unique_days'].replace(0, 1)
    profile['avg_files_modified_per_day'] = profile['write_files'] / profile['unique_days'].replace(0, 1)
    profile['sensitive_file_pct'] = profile['sensitive_files'] / profile['total_files'].replace(0, 1)
    
    profile.drop(columns=['unique_days', 'write_files', 'sensitive_files'], inplace=True)
    return profile

def build_email_profile(email_df: pd.DataFrame) -> pd.DataFrame:
    """
    Build user email profiles.
    
    Args:
        email_df: DataFrame containing email events.
        
    Returns:
        DataFrame indexed by user with email profile metrics.
    """
    if email_df.empty:
        return pd.DataFrame()
        
    df = email_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df['date']):
        df['date'] = pd.to_datetime(df['date'])
        
    df['date_only'] = df['date'].dt.date
    if 'is_external' not in df.columns:
        df['is_external'] = False
    if 'has_attachment' not in df.columns:
        df['has_attachment'] = df['attachments'].notna() & (df['attachments'] != '') & (df['attachments'] != 0) if 'attachments' in df.columns else False
    
    def count_recipients(row):
        cols = ['to', 'cc', 'bcc']
        count = 0
        for col in cols:
            if col in df.columns and pd.notna(row[col]) and str(row[col]).strip() != '':
                count += len(str(row[col]).split(';'))
        return count if count > 0 else 1

    df['num_recipients'] = df.apply(count_recipients, axis=1)

    profile = df.groupby('user').agg(
        total_emails=('id', 'count'),
        unique_days=('date_only', 'nunique'),
        external_emails=('is_external', 'sum'),
        attachment_emails=('has_attachment', 'sum'),
        total_recipients=('num_recipients', 'sum')
    )
    
    profile['avg_emails_per_day'] = profile['total_emails'] / profile['unique_days'].replace(0, 1)
    profile['external_email_pct'] = profile['external_emails'] / profile['total_emails'].replace(0, 1)
    profile['attachment_pct'] = profile['attachment_emails'] / profile['total_emails'].replace(0, 1)
    profile['avg_recipients'] = profile['total_recipients'] / profile['total_emails'].replace(0, 1)
    
    profile.drop(columns=['unique_days', 'external_emails', 'attachment_emails', 'total_recipients'], inplace=True)
    return profile

def build_device_profile(device_df: pd.DataFrame) -> pd.DataFrame:
    """
    Build user device profiles.
    
    Args:
        device_df: DataFrame containing device events.
        
    Returns:
        DataFrame indexed by user with device profile metrics.
    """
    if device_df.empty:
        return pd.DataFrame()
        
    df = device_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df['date']):
        df['date'] = pd.to_datetime(df['date'])
    
    df['week_yr'] = df['date'].dt.strftime('%Y-%U')
    
    # Filter for connects
    connects = df[df['activity'].str.lower() == 'connect'] if 'activity' in df.columns else df
    
    profile = connects.groupby('user').agg(
        total_usb_connections=('id', 'count'),
        unique_weeks=('week_yr', 'nunique')
    )
    
    profile['usb_sessions_per_week'] = profile['total_usb_connections'] / profile['unique_weeks'].replace(0, 1)
    profile['has_usb_usage'] = profile['total_usb_connections'] > 0
    
    profile.drop(columns=['unique_weeks'], inplace=True)
    
    # Ensure all users are represented
    all_users = df[['user']].drop_duplicates().set_index('user')
    profile = all_users.join(profile).fillna({'total_usb_connections': 0, 'usb_sessions_per_week': 0, 'has_usb_usage': False})
    
    return profile

def build_web_profile(http_df: pd.DataFrame) -> pd.DataFrame:
    """
    Build user web activity profiles.
    
    Args:
        http_df: DataFrame containing web (http) events.
        
    Returns:
        DataFrame indexed by user with web profile metrics.
    """
    if http_df.empty:
        return pd.DataFrame()
        
    df = http_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df['date']):
        df['date'] = pd.to_datetime(df['date'])
        
    df['date_only'] = df['date'].dt.date
    if 'is_suspicious' not in df.columns:
        df['is_suspicious'] = False
        
    if 'url' in df.columns:
        df['domain'] = df['url'].apply(lambda x: str(x).split('/')[2] if '://' in str(x) else str(x).split('/')[0])
    else:
        df['domain'] = 'unknown'
        
    profile = df.groupby('user').agg(
        total_pages=('id', 'count'),
        unique_days=('date_only', 'nunique'),
        suspicious_site_count=('is_suspicious', 'sum'),
        unique_domains=('domain', 'nunique')
    )
    
    profile['avg_pages_per_day'] = profile['total_pages'] / profile['unique_days'].replace(0, 1)
    
    profile.drop(columns=['unique_days'], inplace=True)
    return profile

def build_all_profiles(datasets: dict) -> pd.DataFrame:
    """
    Build and merge all profiles into a single DataFrame.
    
    Args:
        datasets: Dict containing 'logon', 'file', 'email', 'device', 'http' DataFrames.
        
    Returns:
        Merged DataFrame indexed by user.
    """
    profiles = []
    if 'logon' in datasets:
        profiles.append(build_login_profile(datasets['logon']))
    if 'file' in datasets:
        profiles.append(build_file_profile(datasets['file']))
    if 'email' in datasets:
        profiles.append(build_email_profile(datasets['email']))
    if 'device' in datasets:
        profiles.append(build_device_profile(datasets['device']))
    if 'http' in datasets:
        profiles.append(build_web_profile(datasets['http']))
        
    if not profiles:
        return pd.DataFrame()
        
    merged_profile = profiles[0]
    for p in profiles[1:]:
        if not p.empty:
            merged_profile = merged_profile.join(p, how='outer')
            
    # Fill numerical NaN with 0 for counts/averages
    for col in merged_profile.columns:
        if merged_profile[col].dtype.kind in 'biufc':
            merged_profile[col].fillna(0, inplace=True)
            
    return merged_profile

def get_user_summary(user_id: str, profiles_df: pd.DataFrame) -> dict:
    """
    Get a formatted dictionary summarizing one user's profile.
    
    Args:
        user_id: User identifier.
        profiles_df: Master profile DataFrame.
        
    Returns:
        Dictionary summarizing user's baseline.
    """
    if user_id not in profiles_df.index:
        return {"error": f"User {user_id} not found in profiles."}
        
    return profiles_df.loc[user_id].to_dict()

def compute_deviation(user_id: str, current_value: float, profiles_df: pd.DataFrame, metric: str) -> float:
    """
    Compute how much a user's current activity deviates from their baseline.
    
    Args:
        user_id: User identifier.
        current_value: Current metric value.
        profiles_df: Master profile DataFrame.
        metric: Metric column name in profiles_df.
        
    Returns:
        Deviation ratio.
    """
    if user_id not in profiles_df.index or metric not in profiles_df.columns:
        return 0.0
        
    baseline = profiles_df.loc[user_id, metric]
    if pd.isna(baseline) or baseline == 0:
        return current_value if current_value > 0 else 0.0
        
    return (current_value - baseline) / baseline
