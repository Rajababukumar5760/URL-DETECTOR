"""Optional inference for a separately trained, locally saved model."""
from pathlib import Path
import joblib
import pandas as pd

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "phishing_model.joblib"
FEATURE_COLUMNS = ["url_length", "hostname_length", "hostname_dot_count", "subdomain_count_approx",
                   "is_ip_address", "uses_https", "contains_at_symbol", "hostname_hyphen_count",
                   "hostname_digit_count", "query_parameter_count", "has_suspicious_encoding",
                   "has_misleading_hostname_pattern", "is_known_shortener", "uses_uncommon_tld"]


def model_status() -> dict:
    if not MODEL_PATH.exists():
        return {"available": False, "status": "not_trained", "message": "No trained model artifact is installed; rule-based analysis remains available."}
    try:
        joblib.load(MODEL_PATH)
        return {"available": True, "status": "ready", "message": "A local model artifact is present."}
    except Exception:
        return {"available": False, "status": "incompatible", "message": "The model artifact could not be loaded; rule-based analysis remains available."}


def predict(features: dict) -> dict:
    status = model_status()
    if not status["available"]:
        return status
    try:
        model = joblib.load(MODEL_PATH)
        row = {k: features.get(k, False if k in {"is_ip_address", "uses_https", "contains_at_symbol", "has_suspicious_encoding", "has_misleading_hostname_pattern", "is_known_shortener", "uses_uncommon_tld"} else 0) for k in FEATURE_COLUMNS}
        frame = pd.DataFrame([row], columns=FEATURE_COLUMNS)
        prediction = int(model.predict(frame)[0])
        result = {**status, "prediction": prediction, "label": "phishing-like" if prediction == 1 else "legitimate-like"}
        if hasattr(model, "predict_proba"):
            result["model_score"] = round(float(max(model.predict_proba(frame)[0])), 4)
            result["score_note"] = "Model score is not a calibrated real-world phishing probability."
        return result
    except Exception:
        return {"available": False, "status": "incompatible", "message": "Model inference failed; rule-based analysis remains available."}
