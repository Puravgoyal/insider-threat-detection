import pandas as pd
import numpy as np
import os
import urllib.parse
from typing import Dict, Optional
import logging

try:
    from src import config
except ImportError:
    # Fallback config
    class config:
        WORK_HOUR_START = 8
        WORK_HOUR_END = 18
        SENSITIVE_FILE_EXTENSIONS = ['.doc', '.docx', '.pdf', '.xls', '.xlsx']
        ALL_SUSPICIOUS_DOMAINS = ['wikileaks.org', 'dropbox.com', 'mega.nz']
        DATA_PROCESSED_DIR = "data/processed"

logger = logging.getLogger(__name__)

def parse_timestamps(df: pd.DataFrame, date_col: str = 'date') -> pd.DataFrame:
    """
    Convert date column to pd.Timestamp. Add derived columns: 
    hour, weekday, month, day_of_week, is_weekend, is_after_hours, is_night.
    """
    if df.empty or date_col not in df.columns:
        return df
        
    df = df.copy()
    
    if not pd.api.types.is_datetime64_any_dtype(df[date_col]):
        df[date_col] = pd.to_datetime(df[date_col], format='mixed', errors='coerce')
        
    df['hour'] = df[date_col].dt.hour
    df['weekday'] = df[date_col].dt.day_name()
    df['month'] = df[date_col].dt.month
    df['day_of_week'] = df[date_col].dt.dayofweek
    df['is_weekend'] = df['day_of_week'] >= 5
    
    df['is_after_hours'] = (df['hour'] < config.WORK_HOUR_START) | (df['hour'] >= config.WORK_HOUR_END)
    df['is_night'] = (df['hour'] >= 0) & (df['hour'] < 5)
    
    return df

def clean_logon(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean logon data: parse timestamps, normalize activity column (Logon/Logoff), 
    extract user domain if present.
    """
    if df.empty:
        return df
    
    df = parse_timestamps(df)
    
    if 'activity' in df.columns:
        df['activity'] = df['activity'].str.strip().str.lower()
        
    if 'user' in df.columns:
        df['user_domain'] = df['user'].apply(lambda x: x.split('\\')[0] if isinstance(x, str) and '\\' in x else None)
        df['user_name'] = df['user'].apply(lambda x: x.split('\\')[-1] if isinstance(x, str) and '\\' in x else x)
        
    return df

def clean_file(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean file data: parse timestamps, extract file extension from filename, 
    flag sensitive file types, normalize activity types.
    """
    if df.empty:
        return df
        
    df = parse_timestamps(df)
    
    if 'filename' in df.columns:
        df['file_extension'] = df['filename'].apply(lambda x: os.path.splitext(x)[1].lower() if isinstance(x, str) else '')
        df['is_sensitive_file'] = df['file_extension'].isin(config.SENSITIVE_FILE_EXTENSIONS)
        
    if 'activity' in df.columns:
        df['activity'] = df['activity'].str.strip().str.lower()
        
    return df

def clean_email(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean email data: parse timestamps, extract sender/recipient domains, 
    flag external emails, count recipients, flag emails with attachments.
    """
    if df.empty:
        return df
        
    df = parse_timestamps(df)
    
    def extract_domain(email_str):
        if not isinstance(email_str, str):
            return None
        parts = email_str.split('@')
        if len(parts) > 1:
            return parts[-1]
        return None
        
    if 'from' in df.columns:
        df['sender_domain'] = df['from'].apply(extract_domain)
        # Find internal domain (most common)
        if not df['sender_domain'].empty:
            internal_domain = df['sender_domain'].mode()[0] if len(df['sender_domain'].mode()) > 0 else None
            df['is_external'] = df['sender_domain'] != internal_domain
            
    df['recipient_count'] = 0
    for col in ['to', 'cc', 'bcc']:
        if col in df.columns:
            df['recipient_count'] += df[col].apply(lambda x: len(x.split(';')) if isinstance(x, str) and x else 0)
            
    if 'attachments' in df.columns:
        df['has_attachments'] = df['attachments'].apply(
            lambda x: True if pd.notnull(x) and str(x).strip() not in ['', '0'] else False
        )
        
    return df

def clean_http(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean HTTP data: parse timestamps, extract domain from URL, 
    flag suspicious domains.
    """
    if df.empty:
        return df
        
    df = parse_timestamps(df)
    
    if 'url' in df.columns:
        def get_domain(url_str):
            if not isinstance(url_str, str):
                return None
            if not url_str.startswith('http'):
                url_str = 'http://' + url_str
            try:
                parsed = urllib.parse.urlparse(url_str)
                return parsed.netloc.lower()
            except:
                return None
                
        df['domain'] = df['url'].apply(get_domain)
        df['is_suspicious_domain'] = df['domain'].apply(
            lambda x: any(sus in x for sus in config.ALL_SUSPICIOUS_DOMAINS) if x else False
        )
        
    if 'activity' in df.columns:
        df['activity'] = df['activity'].str.strip().str.lower()
        
    return df

def clean_device(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean device data: parse timestamps, normalize activity, 
    identify USB sessions (pair connect/disconnect).
    """
    if df.empty:
        return df
        
    df = parse_timestamps(df)
    
    if 'activity' in df.columns:
        df['activity'] = df['activity'].str.strip().str.lower()
        
    return df

def preprocess_all(datasets: Dict[str, pd.DataFrame]) -> Dict[str, pd.DataFrame]:
    """
    Orchestrate all cleaning functions. Takes dict of raw DataFrames, 
    returns dict of cleaned DataFrames. Also saves cleaned data.
    """
    cleaned = {}
    
    clean_funcs = {
        'logon': clean_logon,
        'file': clean_file,
        'email': clean_email,
        'http': clean_http,
        'device': clean_device
    }
    
    os.makedirs(config.DATA_PROCESSED_DIR, exist_ok=True)
    
    for name, df in datasets.items():
        print(f"  Cleaning {name} dataset ({len(df):,} rows)...")
        if name in clean_funcs:
            cleaned_df = clean_funcs[name](df)
        else:
            cleaned_df = parse_timestamps(df)

        # Rename is_sensitive_file -> is_sensitive for consistency with feature engineering
        if 'is_sensitive_file' in cleaned_df.columns and 'is_sensitive' not in cleaned_df.columns:
            cleaned_df['is_sensitive'] = cleaned_df['is_sensitive_file']

        cleaned[name] = cleaned_df
        
        # Only save smaller datasets to disk (skip http which can be huge)
        if len(cleaned_df) < 1_000_000:
            out_path = os.path.join(str(config.DATA_PROCESSED_DIR), f"{name}_clean.csv")
            try:
                cleaned_df.to_csv(out_path, index=False)
                print(f"    Saved cleaned {name} to {out_path}")
            except Exception as e:
                logger.error(f"Error saving {name}: {e}")
        else:
            print(f"    Skipping save for {name} (too large: {len(cleaned_df):,} rows)")
            
    return cleaned
