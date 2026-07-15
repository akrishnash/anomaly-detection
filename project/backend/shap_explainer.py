import os
import pickle
import numpy as np
import shap

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
_explainer = None
_feature_names = None

PRETTY_NAMES = {
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "fwd_bytes": "Fwd Packet Bytes",
    "bwd_bytes": "Bwd Packet Bytes",
    "total_pkts": "Total Packet Count",
    "syn_flag": "SYN Flag Count",
    "rst_flag": "RST Flag Count",
    "fin_flag": "FIN Flag Count",
    "flow_duration_s": "Flow Duration",
    "pkt_len_mean": "Packet Length Mean"
}


def load_explainer():
    global _explainer, _feature_names
    if _explainer is not None:
        return _explainer, _feature_names

    if_path = os.path.join(MODELS_DIR, "isolation_forest.pkl")
    meta_path = os.path.join(MODELS_DIR, "meta.pkl")

    if not os.path.exists(if_path) or not os.path.exists(meta_path):
        raise FileNotFoundError("Models or metadata files not found. Train the models first.")

    with open(if_path, "rb") as f:
        if_model = pickle.load(f)
    with open(meta_path, "rb") as f:
        meta = pickle.load(f)

    _feature_names = meta["features"]
    # TreeExplainer natively supports sklearn IsolationForest. Its output is the
    # (negated) anomaly path length, so NEGATIVE shap values push toward "anomalous"
    # (shorter isolation paths). We flip the sign so positive impact = more anomalous.
    _explainer = shap.TreeExplainer(if_model)

    return _explainer, _feature_names


def _build_result(row_shap: np.ndarray, feature_names: list) -> tuple[list[dict], str]:
    contributions = []
    for name, val in zip(feature_names, row_shap):
        # Flip sign: for IsolationForest, lower model output = more anomalous
        impact = -float(val)
        contributions.append({
            "feature": name,
            "display_name": PRETTY_NAMES.get(name, name),
            "impact": impact
        })

    contributions_sorted = sorted(contributions, key=lambda x: abs(x["impact"]), reverse=True)

    # Gather top features with positive impacts (which pushed the flow towards anomalous)
    positive_impacts = [c for c in contributions_sorted if c["impact"] > 0.01]

    if len(positive_impacts) > 0:
        top_features = [c["display_name"] for c in positive_impacts[:4]]
        if len(top_features) > 1:
            features_text = ", ".join(top_features[:-1]) + f", and {top_features[-1]}"
        else:
            features_text = top_features[0]
        text_explanation = f"The flow was flagged as highly suspicious mainly because {features_text} contributed the most to the anomaly signature."
    else:
        text_explanation = "The anomaly was detected due to a combination of subtle deviations from the baseline traffic profile."

    return contributions_sorted, text_explanation


def explain_prediction(X_scaled_row: np.ndarray) -> tuple[list[dict], str]:
    """
    Computes local SHAP values for a single flow record (10 scaled features).
    Returns:
        contributions: List of dicts representing feature and its SHAP value impact.
        text_explanation: Natural language explanation summarizing main causes of threat.
    """
    explainer, feature_names = load_explainer()
    row_input = X_scaled_row.reshape(1, -1)
    shap_values = explainer(row_input).values[0]
    return _build_result(shap_values, feature_names)


def explain_predictions_batch(X_scaled_matrix: np.ndarray) -> list[tuple[list[dict], str]]:
    """
    Computes local SHAP values for a batch of flow records for massive performance.
    """
    if len(X_scaled_matrix) == 0:
        return []

    explainer, feature_names = load_explainer()
    shap_values = explainer(X_scaled_matrix).values

    return [_build_result(shap_values[i], feature_names) for i in range(len(X_scaled_matrix))]
