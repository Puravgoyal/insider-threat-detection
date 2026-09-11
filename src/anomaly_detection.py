"""
Anomaly detection module for Insider Threat Detection.
Provides functions for preparing feature matrices, training Isolation Forest,
and predicting anomalies.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.inspection import permutation_importance
from src import config

def prepare_feature_matrix(features_df):
    """
    Prepare the feature matrix for anomaly detection.

    Args:
        features_df (pd.DataFrame): User x feature DataFrame.

    Returns:
        tuple: (scaled_matrix, scaler, feature_names, user_index)
    """
    if features_df.empty:
        return np.array([]), None, [], []

    # Assume 'user' might be the index, or it might be a column.
    if 'user' in features_df.columns:
        user_index = features_df['user'].values
        features_df = features_df.set_index('user')
    else:
        user_index = features_df.index.values

    # Select only numeric columns
    numeric_df = features_df.select_dtypes(include=[np.number])
    feature_names = numeric_df.columns.tolist()

    # Handle NaNs by filling with 0
    numeric_df = numeric_df.fillna(0)

    # Standardize
    scaler = StandardScaler()
    scaled_matrix = scaler.fit_transform(numeric_df)

    return scaled_matrix, scaler, feature_names, user_index

def train_isolation_forest(scaled_matrix, params=None):
    """
    Train Isolation Forest model.

    Args:
        scaled_matrix (np.ndarray): Scaled feature matrix.
        params (dict, optional): Hyperparameters. Defaults to config.ISOLATION_FOREST_PARAMS.

    Returns:
        IsolationForest: Fitted model.
    """
    if params is None:
        params = getattr(config, 'ISOLATION_FOREST_PARAMS', {})
    
    model = IsolationForest(**params)
    if len(scaled_matrix) > 0:
        model.fit(scaled_matrix)
    return model

def get_anomaly_scores(model, scaled_matrix, user_index):
    """
    Get anomaly scores from the trained model and normalize to 0-100 scale.

    Args:
        model (IsolationForest): Trained model.
        scaled_matrix (np.ndarray): Scaled feature matrix.
        user_index (np.ndarray): User identifiers.

    Returns:
        pd.DataFrame: DataFrame with [user, anomaly_score, is_anomaly].
    """
    if len(scaled_matrix) == 0:
        return pd.DataFrame(columns=['user', 'anomaly_score', 'is_anomaly'])
    
    # decision_function returns negative values for outliers, positive for inliers
    raw_scores = model.decision_function(scaled_matrix)
    predictions = model.predict(scaled_matrix)
    
    # Normalize roughly from range [-0.5, 0.5] to [0, 100]
    # Lower raw score -> Higher anomaly score
    normalized_scores = 100 * (0.5 - raw_scores)
    normalized_scores = np.clip(normalized_scores, 0, 100)
    
    df = pd.DataFrame({
        'user': user_index,
        'anomaly_score': normalized_scores,
        'is_anomaly': predictions == -1
    })
    return df

def get_anomaly_predictions(model, scaled_matrix, user_index):
    """
    Get binary predictions (-1 = anomaly, 1 = normal).

    Args:
        model (IsolationForest): Trained model.
        scaled_matrix (np.ndarray): Scaled feature matrix.
        user_index (np.ndarray): User identifiers.

    Returns:
        pd.DataFrame: DataFrame with [user, prediction, is_anomaly].
    """
    if len(scaled_matrix) == 0:
        return pd.DataFrame(columns=['user', 'prediction', 'is_anomaly'])
    
    predictions = model.predict(scaled_matrix)
    return pd.DataFrame({
        'user': user_index,
        'prediction': predictions,
        'is_anomaly': predictions == -1
    })

def get_feature_importance(model, scaled_matrix, feature_names, user_index):
    """
    Approximate feature importance using permutation importance.

    Args:
        model (IsolationForest): Trained model.
        scaled_matrix (np.ndarray): Scaled feature matrix.
        feature_names (list): List of feature names.
        user_index (np.ndarray): User identifiers.

    Returns:
        pd.DataFrame: DataFrame of feature importances sorted descending.
    """
    if len(scaled_matrix) == 0:
        return pd.DataFrame(columns=['feature', 'importance'])
        
    def scorer(estimator, X, y=None):
        return np.mean(estimator.decision_function(X))
        
    result = permutation_importance(model, scaled_matrix, None, scoring=scorer, n_repeats=5, random_state=42)
    
    importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': result.importances_mean
    })
    return importance_df.sort_values(by='importance', ascending=False)

def detect_anomalies(features_df):
    """
    End-to-end function: prepare, train, score, and return results.

    Args:
        features_df (pd.DataFrame): User features DataFrame.

    Returns:
        pd.DataFrame: DataFrame with [user, anomaly_score, is_anomaly, prediction].
    """
    scaled_matrix, scaler, feature_names, user_index = prepare_feature_matrix(features_df)
    
    if len(scaled_matrix) == 0:
        return pd.DataFrame(columns=['user', 'anomaly_score', 'is_anomaly', 'prediction'])
        
    model = train_isolation_forest(scaled_matrix)
    scores_df = get_anomaly_scores(model, scaled_matrix, user_index)
    preds_df = get_anomaly_predictions(model, scaled_matrix, user_index)
    
    result_df = pd.merge(scores_df, preds_df[['user', 'prediction']], on='user')
    return result_df
