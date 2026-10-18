# Evaluation Module for Objectives 1 & 2
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)


def compute_metrics(y_true, y_pred, y_scores=None, model_name="Model"):
    """
    Computes rigorous empirical evaluation metrics against ground-truth labels y_true.
    Strictly used for post-prediction evaluation; labels are never seen during training.
    """
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    total = len(y_true)
    detected_anomalies = int(np.sum(y_pred))
    detected_anomaly_pct = (detected_anomalies / total) * 100.0

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    roc_auc = 'N/A'
    pr_auc = 'N/A'
    if y_scores is not None:
        try:
            roc_auc = round(float(roc_auc_score(y_true, y_scores)), 4)
        except Exception:
            pass
        try:
            pr_auc = round(float(average_precision_score(y_true, y_scores)), 4)
        except Exception:
            pass

    return {
        'model_name': model_name,
        'total_samples': total,
        'normal_samples': int((y_true == 0).sum()),
        'anomalous_samples': int((y_true == 1).sum()),
        'detected_anomalies': detected_anomalies,
        'detected_anomaly_percentage': round(detected_anomaly_pct, 2),
        'accuracy': round(acc * 100.0, 2),
        'precision': round(prec * 100.0, 2),
        'recall': round(rec * 100.0, 2),
        'f1_score': round(f1 * 100.0, 2),
        'roc_auc': roc_auc,
        'pr_auc': pr_auc,
        'false_positive_rate': round(fpr * 100.0, 2),
        'false_negative_rate': round(fnr * 100.0, 2),
        'confusion_matrix': {
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'true_positives': int(tp)
        }
    }
