"""
data_loader.py - Dataset Loading and Inspection
=================================================
Load and inspect the raw CERT Insider Threat Dataset CSV files.
Handles large files (e.g. http.csv) via sampling to avoid memory issues.
"""
import pandas as pd
import os
import logging
from typing import Dict, Optional, List
from pathlib import Path

try:
    from src import config
except ImportError:
    class config:
        DATA_RAW_DIR = Path("data/raw")
        DATASET_FILES = {
            'logon': Path('data/raw/logon.csv'),
            'file': Path('data/raw/file.csv'),
            'email': Path('data/raw/email.csv'),
            'http': Path('data/raw/http.csv'),
            'device': Path('data/raw/device.csv'),
        }

logger = logging.getLogger(__name__)

# Maximum rows to load for very large files (e.g. http.csv at 14+ GB)
MAX_ROWS_LARGE_FILE = 500_000
LARGE_FILE_THRESHOLD_MB = 500  # Files above this size get sampled


def load_dataset(filepath: str, name: Optional[str] = None, verbose: bool = True,
                 max_rows: Optional[int] = None) -> pd.DataFrame:
    """
    Load a single CSV file into a DataFrame.
    
    Args:
        filepath: Path to the CSV file.
        name: Human-readable name for the dataset.
        verbose: If True, print info about the loaded dataset.
        max_rows: If set, only load this many rows (for large files).
        
    Returns:
        pd.DataFrame (empty on error).
    """
    filepath = str(filepath)
    if not os.path.exists(filepath):
        logger.warning(f"File not found: {filepath}")
        if verbose:
            print(f"  WARNING: {name or 'Dataset'} not found at {filepath}")
        return pd.DataFrame()

    try:
        # Check file size
        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
        
        if max_rows is None and file_size_mb > LARGE_FILE_THRESHOLD_MB:
            max_rows = MAX_ROWS_LARGE_FILE
            if verbose:
                print(f"  NOTE: {name or 'Dataset'} is {file_size_mb:.0f} MB — "
                      f"sampling {max_rows:,} rows to avoid memory issues.")

        if max_rows:
            df = pd.read_csv(filepath, nrows=max_rows)
        else:
            df = pd.read_csv(filepath)

        # Parse date column if present
        if 'date' in df.columns:
            df['date'] = pd.to_datetime(df['date'], format='mixed', errors='coerce')

        if verbose:
            size_str = f" ({file_size_mb:.0f} MB)" if file_size_mb > 10 else ""
            sample_str = f" [sampled from {max_rows:,}]" if max_rows else ""
            print(f"  Loaded {name or 'dataset'}: {df.shape[0]:,} rows, "
                  f"{df.shape[1]} cols{size_str}{sample_str}")
        return df
    except Exception as e:
        logger.error(f"Error loading {filepath}: {e}")
        if verbose:
            print(f"  ERROR loading {name or 'dataset'}: {e}")
        return pd.DataFrame()


def load_all_datasets(data_dir: Optional[str] = None) -> Dict[str, pd.DataFrame]:
    """
    Load all 5 datasets (logon, file, email, http, device) from data/raw/.
    
    Large files (>500 MB) are automatically sampled to avoid memory issues.
    
    Args:
        data_dir: Override directory for raw data. Uses config default if None.
        
    Returns:
        Dict mapping dataset name to DataFrame.
    """
    if data_dir is None:
        data_dir = str(config.DATA_RAW_DIR)

    datasets = {}
    for name, filepath in config.DATASET_FILES.items():
        full_path = str(filepath)
        if not os.path.exists(full_path):
            # Try joining with data_dir
            alt_path = os.path.join(data_dir, f"{name}.csv")
            if os.path.exists(alt_path):
                full_path = alt_path
            else:
                print(f"  SKIP: {name}.csv not found")
                continue

        datasets[name] = load_dataset(full_path, name=name)

    return datasets


def inspect_dataset(df: pd.DataFrame, name: str = 'Dataset'):
    """
    Print comprehensive inspection of a dataset.
    
    Shows: shape, columns, dtypes, missing values, unique users, date range,
    and first 5 rows.
    """
    print(f"\n--- {name} ---")
    print(f"Shape: {df.shape[0]:,} rows x {df.shape[1]} columns")
    print(f"Columns: {list(df.columns)}")
    
    print("\nData Types:")
    for col in df.columns:
        print(f"  {col:20s} {str(df[col].dtype):15s} "
              f"({df[col].isnull().sum():,} missing)")

    if 'user' in df.columns:
        print(f"\nUnique users: {df['user'].nunique():,}")
    elif 'user_id' in df.columns:
        print(f"\nUnique users: {df['user_id'].nunique():,}")

    if 'date' in df.columns and not df['date'].isnull().all():
        print(f"Date range: {df['date'].min()} to {df['date'].max()}")

    print(f"\nSample rows:")
    print(df.head(3).to_string())
    print("-" * 50)


def generate_dataset_summary(datasets: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """
    Create a summary table of all loaded datasets.
    
    Returns:
        DataFrame with columns: Dataset, Records, Users, Date Range, Key Fields.
    """
    summary = []
    for name, df in datasets.items():
        if df.empty:
            continue

        records = df.shape[0]

        user_col = 'user' if 'user' in df.columns else (
            'user_id' if 'user_id' in df.columns else None)
        users = df[user_col].nunique() if user_col else 0

        if 'date' in df.columns and not df['date'].isnull().all():
            date_min = df['date'].min()
            date_max = df['date'].max()
            date_range = f"{date_min.strftime('%Y-%m-%d')} to {date_max.strftime('%Y-%m-%d')}"
        else:
            date_range = "N/A"

        key_fields = ", ".join(list(df.columns)[:6])

        summary.append({
            'Dataset': name.upper(),
            'Records': f"{records:,}",
            'Users': users,
            'Date Range': date_range,
            'Key Fields': key_fields
        })

    return pd.DataFrame(summary)


def check_data_availability(data_dir: Optional[str] = None) -> List[str]:
    """
    Check which dataset files exist in the data directory.
    
    Returns:
        List of available dataset names.
    """
    if data_dir is None:
        data_dir = str(config.DATA_RAW_DIR)

    available = []
    for name, filepath in config.DATASET_FILES.items():
        full_path = str(filepath)
        exists = os.path.exists(full_path)
        if not exists:
            alt_path = os.path.join(data_dir, f"{name}.csv")
            exists = os.path.exists(alt_path)
        
        file_size = ""
        if exists:
            try:
                size_mb = os.path.getsize(full_path if os.path.exists(full_path) else alt_path) / (1024*1024)
                file_size = f" ({size_mb:.0f} MB)"
            except:
                pass
        
        status = "FOUND" + file_size if exists else "MISSING"
        print(f"  {name:10s} ({name}.csv): {status}")
        if exists:
            available.append(name)

    return available
