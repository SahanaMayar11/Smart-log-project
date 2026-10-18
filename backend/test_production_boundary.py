import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import sklearn
import joblib
import numpy as np
import pandas as pd
from ml_engine import IsolationForestDetector, FEATURE_SCHEMA

print(f"Scikit-Learn Version: {sklearn.__version__}")

# Load production model
model_path = os.path.join(os.path.dirname(__file__), 'models', 'isolation_forest_model.pkl')
model = joblib.load(model_path)
print(f"Loaded Model Type   : {type(model)}")
print(f"Offset (Threshold)  : {getattr(model, 'offset_', 'N/A')}")
print(f"Contamination       : {getattr(model, 'contamination', 'N/A')}")

# We will sweep features across a grid to find samples spanning decision_function from negative to positive
# In Isolation Forest: decision_function(X) = score_samples(X) - offset_
# predict(X) returns -1 for outliers (anomalies) and +1 for inliers (normal)

# Let's create a fine-grained sweep of sequence_length and error_count and event_frequency
samples = []
for seq_len in np.linspace(10, 500, 50):
    for err in [0, 1, 2, 5, 10, 20, 50]:
        for freq in [0.01, 0.1, 0.5, 0.8, 1.0]:
            for fail_login in [0, 1, 5, 20]:
                samples.append({
                    'event_frequency': freq,
                    'sequence_length': seq_len,
                    'error_count': float(err),
                    'error_pattern': 1.0 if err > 0 else 0.0,
                    'login_attempts': float(fail_login),
                    'failed_login_attempts': float(fail_login),
                    'warning_count': 0.0,
                    'unknown_events': 0.0
                })

df = pd.DataFrame(samples)
dec_scores = model.decision_function(df)
preds = model.predict(df)

# Check standard scikit-learn rule:
# predict(X) == 1 when decision_function(X) >= 0 (or > 0)
# predict(X) == -1 when decision_function(X) < 0 (or <= 0)

print(f"\nTotal synthetic search samples: {len(df)}")
print(f"Min decision_function: {dec_scores.min():.6f}")
print(f"Max decision_function: {dec_scores.max():.6f}")

# Find samples closest to zero on both positive and negative sides
pos_mask = dec_scores >= 0
neg_mask = dec_scores < 0

pos_scores = dec_scores[pos_mask]
pos_preds = preds[pos_mask]
pos_df = df[pos_mask]

neg_scores = dec_scores[neg_mask]
neg_preds = preds[neg_mask]
neg_df = df[neg_mask]

print(f"\nPositive decision_function samples (Inliers): {len(pos_scores)}")
print(f"Negative decision_function samples (Outliers): {len(neg_scores)}")

# Find closest positive and negative samples
pos_indices = np.where(dec_scores > 0)[0]
neg_indices = np.where(dec_scores < 0)[0]

closest_pos = pos_indices[np.argsort(dec_scores[pos_indices])[:5]]
closest_neg = neg_indices[np.argsort(-dec_scores[neg_indices])[:5]]

combined_boundary_indices = np.concatenate([closest_pos, closest_neg])

print("\n" + "="*85)
print(f"{'Sample #':8s} | {'decision_function':18s} | {'sklearn predict()':18s} | {'norm_score':12s} | {'is_anomaly':10s} | {'Severity':10s}")
print("="*85)

for idx in combined_boundary_indices:
    df_row = df.iloc[[idx]]
    s_dec = float(model.decision_function(df_row)[0])
    s_pred = int(model.predict(df_row)[0])
    is_anom = 1 if s_pred == -1 else 0
    norm_score = float(np.clip(1.0 - (s_dec + 0.5), 0.0, 1.0))
    
    if norm_score >= 0.50:
        if norm_score > 0.85:
            sev = 'Critical'
        elif norm_score > 0.70:
            sev = 'High'
        elif norm_score > 0.55:
            sev = 'Medium'
        else:
            sev = 'Low'
    else:
        sev = 'Normal'
        
    print(f"{idx:8d} | {s_dec:+18.6f} | {s_pred:+18d} | {norm_score:12.4f} | {is_anom:10d} | {sev:10s}")

print("="*85)

# Test direct IsolationForestDetector with active production model
os.environ['SMARTLOG_IF_MODEL'] = 'active'
detector_active = IsolationForestDetector()
det_results, _ = detector_active.predict(df.iloc[combined_boundary_indices])
print("\nDirect IsolationForestDetector(model='active') results on boundary samples:")
for idx, r in zip(combined_boundary_indices, det_results):
    print(f"  Sample #{idx:4d} | is_anomaly={r['is_anomaly']} | anomaly_score={r['anomaly_score']:.4f} | severity={r['severity']}")


