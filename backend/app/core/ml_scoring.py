import json
import pickle
from functools import lru_cache
from pathlib import Path
from ..ml.features import extract_features

MODEL_DIR = Path(__file__).resolve().parents[1] / 'ml' / 'models'


@lru_cache(maxsize=1)
def models():
    path = MODEL_DIR / 'risk.pkl'
    if not path.exists():
        return None
    # Only developer-produced bundled models are loaded. Uploads never reach this path.
    with path.open('rb') as handle:
        return pickle.load(handle)


def score(s):
    bundle = models()
    if not bundle:
        return
    x = [extract_features(s)]
    s.ml_status = 'synthetic_training_demo'
    s.ml_risk_class = str(bundle['classifier'].predict(x)[0])
    s.ml_anomaly_score = round(float(bundle['anomaly'].decision_function(x)[0]), 5)
    s.ml_is_anomaly = bool(bundle['anomaly'].predict(x)[0] == -1)


def metadata():
    path = MODEL_DIR / 'evaluation.json'
    return json.loads(path.read_text()) if path.exists() else {'status': 'unavailable', 'message': 'Run the offline training script to enable ML.'}
