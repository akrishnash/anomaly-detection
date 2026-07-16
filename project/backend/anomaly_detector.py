"""
Stage 1: fully unsupervised anomaly detection.

Combines the Isolation Forest anomaly score and the Autoencoder reconstruction
error into a single calibrated ensemble probability in [0, 1]. Calibration
anchors are fitted at training time (see train_models.py) and stored in
meta.pkl; inference requires no labels.

The two detectors are fused with an OR-style union (max of the two calibrated
scores): a flow is anomalous if EITHER head considers it anomalous. The heads
are close to conditionally independent on network flow data, so the union
recovers attacks that a single head misses.
"""
import numpy as np

import preprocessing
import isolation_forest


def _calibrate(raw_scores: np.ndarray, anchors: dict) -> np.ndarray:
    """Maps raw scores to [0, 1] via a piecewise-linear ramp: lo->0.0, mid->0.5, hi->1.0."""
    return np.interp(
        raw_scores,
        [anchors["lo"], anchors["mid"], anchors["hi"]],
        [0.0, 0.5, 1.0]
    )


def score_flows_detailed(X_scaled: np.ndarray) -> dict:
    """
    Scores preprocessed (scaled) flows and returns every intermediate value of
    the ensemble decision, so callers can reconstruct WHY a flow was flagged:
        probs:     Calibrated ensemble anomaly probability in [0, 1]
                   (union/max fusion of the two calibrated heads).
        if_scores: Raw Isolation Forest anomaly scores (higher = more anomalous).
        ae_scores: Raw Autoencoder reconstruction errors (higher = more anomalous).
        if_probs:  Isolation Forest score calibrated to [0, 1].
        ae_probs:  Autoencoder error calibrated to [0, 1].
    """
    _, meta, _ = preprocessing.load_preprocessor_assets()
    calibration = meta.get("calibration")
    if calibration is None:
        raise RuntimeError(
            "meta.pkl has no 'calibration' anchors. Retrain models with "
            "train_models.py to generate the unsupervised ensemble calibration."
        )

    if_scores = isolation_forest.compute_anomaly_scores(X_scaled)
    ae_scores = preprocessing.compute_autoencoder_scores(X_scaled)

    if_probs = np.nan_to_num(_calibrate(if_scores, calibration["if"]), nan=0.0, posinf=1.0, neginf=0.0)
    ae_probs = np.nan_to_num(_calibrate(ae_scores, calibration["ae"]), nan=0.0, posinf=1.0, neginf=0.0)

    # Union fusion: alert if either unsupervised head fires
    probs = np.maximum(if_probs, ae_probs)

    return {
        "probs": probs,
        "if_scores": if_scores,
        "ae_scores": ae_scores,
        "if_probs": if_probs,
        "ae_probs": ae_probs,
    }


def score_flows(X_scaled: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Scores preprocessed (scaled) flows with the unsupervised ensemble.
    Returns:
        probs: Calibrated ensemble anomaly probability in [0, 1]. Flows with
               probs >= confidence_threshold (default 0.5) are treated as anomalies.
        if_scores: Raw Isolation Forest anomaly scores (higher = more anomalous).
        ae_scores: Raw Autoencoder reconstruction errors (higher = more anomalous).
    """
    detail = score_flows_detailed(X_scaled)
    return detail["probs"], detail["if_scores"], detail["ae_scores"]
