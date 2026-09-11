import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.dates as mdates
from typing import Dict, List, Optional, Any

from src import config

# Try setting the preferred plot style
try:
    plt.style.use('seaborn-v0_8-darkgrid')
except OSError:
    try:
        plt.style.use('seaborn-darkgrid')
    except OSError:
        plt.style.use('ggplot')


def _save_fig(fig, filename: str, save: bool):
    """Save a figure if requested, handling DPI and tight layout."""
    if save:
        os.makedirs(config.FIGURES_DIR, exist_ok=True)
        filepath = os.path.join(config.FIGURES_DIR, filename)
        fig.tight_layout()
        fig.savefig(filepath, dpi=config.FIGURE_DPI)


def plot_activity_by_user(features_df: pd.DataFrame, top_n: int = 20, save: bool = True) -> plt.Figure:
    """Plot total activity count for the most active users."""
    fig, ax = plt.subplots(figsize=(10, 8))
    
    if features_df is None or features_df.empty:
        ax.text(0.5, 0.5, "No feature data available", ha='center', va='center')
        return fig

    # Compute total activity (dummy summing all count-related columns if not explicitly available)
    # Using 'total_activity' if present, otherwise sum all numeric columns as a proxy
    if 'total_activity' in features_df.columns:
        counts = features_df.set_index('user')['total_activity']
    else:
        # Sum numeric features roughly correlated to counts
        num_cols = features_df.select_dtypes(include=[np.number]).columns
        counts = features_df[num_cols].sum(axis=1)

    top_users = counts.nlargest(top_n).sort_values(ascending=True)
    
    colors = sns.color_palette("viridis", len(top_users))
    top_users.plot(kind='barh', ax=ax, color=colors)
    
    ax.set_title(f"Top {top_n} Most Active Users", fontsize=14, pad=15)
    ax.set_xlabel("Total Activity Events")
    ax.set_ylabel("User ID")
    
    _save_fig(fig, 'activity_by_user.png', save)
    return fig


def plot_activity_by_hour(datasets: Dict[str, pd.DataFrame], save: bool = True) -> plt.Figure:
    """Plot activity count by hour of day across log types."""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    colors = sns.color_palette("husl", 5)
    
    has_data = False
    for idx, (log_type, df) in enumerate(datasets.items()):
        if df is not None and not df.empty and 'date' in df.columns:
            has_data = True
            # Extract hour safely
            if not pd.api.types.is_datetime64_any_dtype(df['date']):
                dates = pd.to_datetime(df['date'], errors='coerce')
            else:
                dates = df['date']
            
            hourly_counts = dates.dt.hour.value_counts().sort_index()
            # Ensure all 24 hours are represented
            hourly_counts = hourly_counts.reindex(range(24), fill_value=0)
            
            ax.plot(hourly_counts.index, hourly_counts.values, marker='o', label=log_type.capitalize(), color=colors[idx % len(colors)])
    
    if not has_data:
        ax.text(0.5, 0.5, "No dataset dates available", ha='center', va='center')
        return fig

    # Highlight after-hours
    ax.axvspan(0, 8, alpha=0.1, color='gray', label='After Hours (12AM-8AM)')
    ax.axvspan(18, 23, alpha=0.1, color='gray', label='After Hours (6PM-11PM)')

    ax.set_title("Activity Count by Hour of Day", fontsize=14, pad=15)
    ax.set_xlabel("Hour of Day (0-23)")
    ax.set_ylabel("Event Count")
    ax.set_xticks(range(24))
    ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    
    _save_fig(fig, 'activity_by_hour.png', save)
    return fig


def plot_normal_vs_suspicious(features_df: pd.DataFrame, scores_df: pd.DataFrame, save: bool = True) -> plt.Figure:
    """Compare average feature values for LOW-risk vs HIGH/CRITICAL-risk users."""
    fig, ax = plt.subplots(figsize=(12, 7))
    
    if features_df is None or features_df.empty or scores_df is None or scores_df.empty:
        ax.text(0.5, 0.5, "Insufficient data for comparison", ha='center', va='center')
        return fig

    merged = pd.merge(features_df, scores_df, on='user')
    if 'risk_level' not in merged.columns:
        ax.text(0.5, 0.5, "No risk levels found", ha='center', va='center')
        return fig
        
    merged['risk_group'] = merged['risk_level'].apply(
        lambda x: 'High/Critical' if x in ['HIGH', 'CRITICAL'] else ('Low/Medium' if x in ['LOW', 'MEDIUM'] else 'Unknown')
    )
    
    # Select some key features
    key_features = ['after_hours_ratio', 'file_deviation', 'usb_count', 'external_email_count']
    available_features = [f for f in key_features if f in merged.columns]
    
    if not available_features:
        # Fallback to numeric columns
        available_features = merged.select_dtypes(include=[np.number]).columns[:5].tolist()
        if 'score' in available_features: available_features.remove('score')
        
    if not available_features:
        ax.text(0.5, 0.5, "No features to compare", ha='center', va='center')
        return fig

    # Calculate means and normalize for display
    grouped = merged.groupby('risk_group')[available_features].mean()
    normalized = grouped / grouped.max()
    
    normalized.T.plot(kind='bar', ax=ax, colormap='Set2')
    
    ax.set_title("Normalized Feature Averages: Normal vs Suspicious", fontsize=14, pad=15)
    ax.set_xlabel("Feature")
    ax.set_ylabel("Normalized Value (0 to 1)")
    ax.set_xticklabels(available_features, rotation=45, ha='right')
    
    _save_fig(fig, 'normal_vs_suspicious.png', save)
    return fig


def plot_usb_usage(features_df: pd.DataFrame, save: bool = True) -> plt.Figure:
    """Plot USB connection counts per user."""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    if features_df is None or 'usb_count' not in features_df.columns or features_df.empty:
        ax.text(0.5, 0.5, "No USB usage data available", ha='center', va='center')
        return fig

    usb_users = features_df[features_df['usb_count'] > 0].sort_values('usb_count', ascending=False).head(30)
    
    if usb_users.empty:
        ax.text(0.5, 0.5, "No users with >0 USB activity", ha='center', va='center')
        return fig
    
    sns.barplot(data=usb_users, x='user', y='usb_count', ax=ax, palette='mako')
    
    ax.set_title("Top USB Usage by User", fontsize=14, pad=15)
    ax.set_xlabel("User ID")
    ax.set_ylabel("USB Connection Count")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha='right')
    
    _save_fig(fig, 'usb_usage.png', save)
    return fig


def plot_external_email(features_df: pd.DataFrame, save: bool = True) -> plt.Figure:
    """Bar chart of external email counts by user."""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    if features_df is None or 'external_email_count' not in features_df.columns or features_df.empty:
        ax.text(0.5, 0.5, "No external email data available", ha='center', va='center')
        return fig

    email_users = features_df.sort_values('external_email_count', ascending=False).head(20)
    
    if email_users.empty or email_users['external_email_count'].max() == 0:
        ax.text(0.5, 0.5, "No external email activity found", ha='center', va='center')
        return fig

    # Highlight if they have attachments
    if 'email_attachment_count' in email_users.columns:
        # Use a secondary metric for color intensity
        sns.barplot(data=email_users, x='user', y='external_email_count', hue='email_attachment_count', ax=ax, palette='flare', dodge=False)
        ax.legend(title="Attachments")
    else:
        sns.barplot(data=email_users, x='user', y='external_email_count', ax=ax, palette='flare')
        
    ax.set_title("Top 20 External Email Senders", fontsize=14, pad=15)
    ax.set_xlabel("User ID")
    ax.set_ylabel("External Email Count")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha='right')
    
    _save_fig(fig, 'external_email.png', save)
    return fig


def plot_daily_activity_timeline(datasets: Dict[str, pd.DataFrame], user_id: Optional[str] = None, save: bool = True) -> plt.Figure:
    """Time series line chart of daily event counts."""
    fig, ax = plt.subplots(figsize=(14, 6))
    
    all_dates = pd.Series(dtype='datetime64[ns]')
    
    for log_type, df in datasets.items():
        if df is not None and not df.empty and 'date' in df.columns:
            subset = df
            if user_id and 'user' in subset.columns:
                subset = subset[subset['user'] == user_id]
            
            if not pd.api.types.is_datetime64_any_dtype(subset['date']):
                dates = pd.to_datetime(subset['date'], errors='coerce').dropna()
            else:
                dates = subset['date'].dropna()
            
            all_dates = pd.concat([all_dates, dates])
            
    if all_dates.empty:
        ax.text(0.5, 0.5, "No timeline data available", ha='center', va='center')
        return fig
        
    daily_counts = all_dates.dt.floor('D').value_counts().sort_index()
    
    ax.plot(daily_counts.index, daily_counts.values, color='steelblue', linewidth=2)
    
    # Highlight spikes (e.g. > 2 std dev)
    mean_val = daily_counts.mean()
    std_val = daily_counts.std()
    spikes = daily_counts[daily_counts > mean_val + 2 * std_val]
    
    if not spikes.empty:
        ax.scatter(spikes.index, spikes.values, color='red', s=50, zorder=5, label='Anomaly/Spike')
        ax.legend()
        
    title = f"Daily Activity Timeline{' for User ' + user_id if user_id else ' (All Users)'}"
    ax.set_title(title, fontsize=14, pad=15)
    ax.set_xlabel("Date")
    ax.set_ylabel("Total Event Count")
    
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
    fig.autofmt_xdate()
    
    _save_fig(fig, f"daily_timeline_{user_id if user_id else 'all'}.png", save)
    return fig


def plot_risk_distribution(scores_df: pd.DataFrame, save: bool = True) -> plt.Figure:
    """Histogram with KDE of risk scores across all users."""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    if scores_df is None or 'score' not in scores_df.columns or scores_df.empty:
        ax.text(0.5, 0.5, "No risk score data available", ha='center', va='center')
        return fig
        
    scores = scores_df['score'].dropna()
    
    sns.histplot(scores, kde=True, ax=ax, color='gray', bins=30)
    
    # Risk boundaries
    ax.axvline(30, color=config.RISK_COLORS.get('LOW', 'green'), linestyle='--', label='Low (<=30)')
    ax.axvline(60, color=config.RISK_COLORS.get('MEDIUM', 'orange'), linestyle='--', label='Medium (<=60)')
    ax.axvline(80, color=config.RISK_COLORS.get('HIGH', 'red'), linestyle='--', label='High (<=80)')
    
    # Color spans
    ax.axvspan(0, 30, alpha=0.1, color=config.RISK_COLORS.get('LOW', 'green'))
    ax.axvspan(30, 60, alpha=0.1, color=config.RISK_COLORS.get('MEDIUM', 'orange'))
    ax.axvspan(60, 80, alpha=0.1, color=config.RISK_COLORS.get('HIGH', 'red'))
    ax.axvspan(80, max(100, scores.max()), alpha=0.1, color=config.RISK_COLORS.get('CRITICAL', 'purple'))
    
    ax.set_title("Distribution of User Risk Scores", fontsize=14, pad=15)
    ax.set_xlabel("Risk Score")
    ax.set_ylabel("Frequency")
    ax.legend(loc='upper right')
    
    _save_fig(fig, 'risk_distribution.png', save)
    return fig


def plot_top_suspicious_users(scores_df: pd.DataFrame, n: int = 10, save: bool = True) -> plt.Figure:
    """Horizontal bar chart of top N users by risk score."""
    fig, ax = plt.subplots(figsize=(10, 8))
    
    if scores_df is None or 'score' not in scores_df.columns or scores_df.empty:
        ax.text(0.5, 0.5, "No risk score data available", ha='center', va='center')
        return fig
        
    top_users = scores_df.nlargest(n, 'score').sort_values('score', ascending=True)
    
    # Map colors by risk level
    if 'risk_level' in top_users.columns:
        colors = [config.RISK_COLORS.get(rl, 'gray') for rl in top_users['risk_level']]
    else:
        colors = ['red'] * len(top_users)
        
    bars = ax.barh(top_users['user'], top_users['score'], color=colors)
    
    # Add score labels
    for bar in bars:
        width = bar.get_width()
        ax.text(width + 1, bar.get_y() + bar.get_height()/2, f'{width:.1f}', ha='left', va='center', fontweight='bold')
        
    ax.set_title(f"Top {n} Most Suspicious Users", fontsize=14, pad=15)
    ax.set_xlabel("Risk Score")
    ax.set_ylabel("User ID")
    ax.set_xlim(0, max(100, top_users['score'].max() * 1.1))
    
    _save_fig(fig, 'top_suspicious_users.png', save)
    return fig


def plot_correlation_heatmap(features_df: pd.DataFrame, save: bool = True) -> plt.Figure:
    """Heatmap of correlation matrix between all numeric features."""
    fig, ax = plt.subplots(figsize=(14, 12))
    
    if features_df is None or features_df.empty:
        ax.text(0.5, 0.5, "No feature data available", ha='center', va='center')
        return fig
        
    num_df = features_df.select_dtypes(include=[np.number])
    if num_df.empty:
        ax.text(0.5, 0.5, "No numeric features for correlation", ha='center', va='center')
        return fig
        
    # Drop columns with zero variance to avoid NA correlation
    num_df = num_df.loc[:, num_df.std() > 0]
    
    corr = num_df.corr()
    
    mask = np.triu(np.ones_like(corr, dtype=bool))
    sns.heatmap(corr, mask=mask, cmap='coolwarm', vmax=1, vmin=-1, center=0,
                square=True, linewidths=.5, cbar_kws={"shrink": .5}, ax=ax, annot=True, fmt=".2f", annot_kws={"size": 8})
    
    ax.set_title("Feature Correlation Heatmap", fontsize=16, pad=20)
    
    _save_fig(fig, 'correlation_heatmap.png', save)
    return fig


def plot_forensic_timeline(timeline_df: pd.DataFrame, user_id: str, save: bool = True) -> plt.Figure:
    """Event timeline visualization for a single user."""
    fig, ax = plt.subplots(figsize=(14, 8))
    
    if timeline_df is None or timeline_df.empty or 'date' not in timeline_df.columns or 'type' not in timeline_df.columns:
        ax.text(0.5, 0.5, "No timeline data available", ha='center', va='center')
        return fig
        
    user_timeline = timeline_df[timeline_df['user'] == user_id]
    if user_timeline.empty:
        ax.text(0.5, 0.5, f"No activity found for user {user_id}", ha='center', va='center')
        return fig
        
    dates = pd.to_datetime(user_timeline['date'])
    
    # Map event types to Y-axis integers
    unique_types = user_timeline['type'].unique()
    type_map = {t: i for i, t in enumerate(unique_types)}
    y_vals = user_timeline['type'].map(type_map)
    
    # Plot points
    sns.scatterplot(x=dates, y=y_vals, hue=user_timeline['type'], style=user_timeline['type'], s=100, ax=ax, palette='tab10')
    
    ax.set_yticks(list(type_map.values()))
    ax.set_yticklabels(list(type_map.keys()))
    
    ax.set_title(f"Forensic Event Timeline for User {user_id}", fontsize=14, pad=15)
    ax.set_xlabel("Time")
    ax.set_ylabel("Event Type")
    
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
    fig.autofmt_xdate()
    ax.grid(True, linestyle='--', alpha=0.7)
    
    _save_fig(fig, f'forensic_timeline_{user_id}.png', save)
    return fig


def plot_risk_radar(user_features: pd.Series, user_id: str, save: bool = True) -> plt.Figure:
    """Radar/spider chart showing a user's risk across different dimensions."""
    fig = plt.figure(figsize=(8, 8))
    
    if user_features is None or user_features.empty:
        plt.text(0.5, 0.5, "No feature data for radar chart", ha='center', va='center')
        return fig
        
    # Pick specific dimensions to visualize
    dimensions = ['after_hours_ratio', 'file_deviation', 'usb_count', 'external_email_count', 'http_upload_size', 'failed_logins']
    actual_dims = [d for d in dimensions if d in user_features.index]
    
    if len(actual_dims) < 3:
        plt.text(0.5, 0.5, "Not enough dimensions for radar chart", ha='center', va='center')
        return fig
        
    # We should normalize these, but for a single user without global context, we just display raw values. 
    # Ideally, values would be percentiles.
    values = [float(user_features[d]) for d in actual_dims]
    
    # Number of variables
    N = len(actual_dims)
    
    # What will be the angle of each axis in the plot? (we divide the plot / number of variable)
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    values += values[:1]
    angles += angles[:1]
    
    ax = plt.subplot(111, polar=True)
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    
    plt.xticks(angles[:-1], actual_dims, size=10)
    
    ax.set_rlabel_position(0)
    plt.yticks(color="grey", size=8)
    
    ax.plot(angles, values, linewidth=2, linestyle='solid', color=config.RISK_COLORS.get('HIGH', 'red'))
    ax.fill(angles, values, color=config.RISK_COLORS.get('HIGH', 'red'), alpha=0.25)
    
    plt.title(f"Risk Dimensions for User {user_id}", size=14, y=1.1)
    
    _save_fig(fig, f'risk_radar_{user_id}.png', save)
    return fig


def create_all_visualizations(features_df: pd.DataFrame, scores_df: pd.DataFrame, datasets: Dict[str, pd.DataFrame], top_users: Optional[List[str]] = None) -> Dict[str, plt.Figure]:
    """Master function that calls all visualization functions and saves everything."""
    figs = {}
    
    figs['activity_by_user'] = plot_activity_by_user(features_df)
    figs['activity_by_hour'] = plot_activity_by_hour(datasets)
    figs['normal_vs_suspicious'] = plot_normal_vs_suspicious(features_df, scores_df)
    figs['usb_usage'] = plot_usb_usage(features_df)
    figs['external_email'] = plot_external_email(features_df)
    
    figs['daily_timeline_all'] = plot_daily_activity_timeline(datasets)
    
    figs['risk_distribution'] = plot_risk_distribution(scores_df)
    figs['top_suspicious'] = plot_top_suspicious_users(scores_df)
    figs['correlation'] = plot_correlation_heatmap(features_df)
    
    # For top users, generate specific forensic charts
    if top_users and len(top_users) > 0:
        # Create a consolidated timeline DF for the top user
        timeline_pieces = []
        for log_type, df in datasets.items():
            if df is not None and not df.empty and 'date' in df.columns and 'user' in df.columns:
                sub = df.copy()
                sub['type'] = log_type
                timeline_pieces.append(sub)
                
        if timeline_pieces:
            timeline_df = pd.concat(timeline_pieces, ignore_index=True)
            
            top_user = top_users[0]
            figs['forensic_timeline'] = plot_forensic_timeline(timeline_df, top_user)
            
            if not features_df.empty and 'user' in features_df.columns:
                user_feat = features_df[features_df['user'] == top_user]
                if not user_feat.empty:
                    figs['risk_radar'] = plot_risk_radar(user_feat.iloc[0], top_user)
    
    return figs
