import hashlib
import json
import math
import pickle
from pathlib import Path

from sklearn.metrics import f1_score, precision_score, recall_score


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def dump_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def session_label(sample: dict) -> int:
    label = sample["label"]
    if isinstance(label, list):
        return int(any(x == 1 for x in label))
    return int(label == 1)


def tokenized_session(sample: dict) -> str:
    tokens = []
    for template in sample["templates"]:
        digest = hashlib.md5(template.encode("utf-8")).hexdigest()[:12]
        tokens.append(f"tpl_{digest}")
    return " ".join(tokens)


def percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    pos = (len(sorted_values) - 1) * (q / 100.0)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = pos - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def evaluate_threshold(scores, y_true, threshold):
    y_pred = [int(score > threshold) for score in scores]
    return {
        "threshold": float(threshold),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "rc": float(recall_score(y_true, y_pred, zero_division=0)),
        "pc": float(precision_score(y_true, y_pred, zero_division=0)),
        "predicted_positive": int(sum(y_pred)),
    }


def compute_event_summary(session_dict: dict, session_scores: dict, threshold: float) -> dict:
    predicted_total_events = 0
    predicted_attack_events = 0
    predicted_normal_events = 0
    predicted_positive = 0
    for session_id, sample in session_dict.items():
        score = session_scores[session_id]
        if score <= threshold:
            continue
        predicted_positive += 1
        total_events = len(sample["templates"])
        label = sample["label"]
        attack_events = int(sum(label)) if isinstance(label, list) else int(label)
        predicted_total_events += total_events
        predicted_attack_events += attack_events
        predicted_normal_events += total_events - attack_events
    return {
        "predicted_positive": predicted_positive,
        "predicted_total_events": predicted_total_events,
        "predicted_attack_events": predicted_attack_events,
        "predicted_normal_events": predicted_normal_events,
    }


def parse_scenario_from_data_dir(data_dir: Path) -> str:
    parts = data_dir.name.split("_vs_")
    if len(parts) == 2:
        return parts[1].upper()
    return data_dir.name.upper()

