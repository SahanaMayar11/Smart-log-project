import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import joblib
import pandas as pd
import numpy as np
import shap
from ml_engine import (
    IsolationForestDetector, FEATURE_SCHEMA, DataPreprocessor,
    LogParser, DataCleaner, BehavioralFeatureExtractor, ShapExplainerEngine
)
from evaluate_models import build_constructed_evaluation_dataset

prod_model_path = os.path.join(os.path.dirname(__file__), 'models', 'isolation_forest_model.pkl')
hdfs_model_path = os.path.join(os.path.dirname(__file__), 'models', 'hdfs_isolation_forest_model.pkl')

print("=== 1. MODEL FILE INSPECTION ===")
for name, p in [('Production IF', prod_model_path), ('HDFS IF', hdfs_model_path)]:
    if os.path.exists(p):
        m = joblib.load(p)
        print(f"{name} ({p}):")
        print(f"  Class: {type(m)}")
        print(f"  n_estimators: {getattr(m, 'n_estimators', None)}")
        print(f"  n_features_in_: {getattr(m, 'n_features_in_', None)}")
        print(f"  feature_names_in_: {getattr(m, 'feature_names_in_', None)}")
        print(f"  max_samples_: {getattr(m, 'max_samples_', None)}")
        print(f"  offset_: {getattr(m, 'offset_', None)}")
    else:
        print(f"{name} ({p}): NOT FOUND")

# 2. Tree split analysis for production model
m = joblib.load(prod_model_path)
split_counts = {f: 0 for f in FEATURE_SCHEMA}
total_splits = 0

for est in m.estimators_:
    tree = est.tree_
    for node in range(tree.node_count):
        feat_idx = tree.feature[node]
        if feat_idx != -2:  # -2 is leaf node
            total_splits += 1
            if feat_idx < len(FEATURE_SCHEMA):
                feat_name = FEATURE_SCHEMA[feat_idx]
                split_counts[feat_name] += 1

print(f"\n=== 2. PRODUCTION MODEL TREE SPLITS (Across {len(m.estimators_)} trees, {total_splits} total splits) ===")
for f, count in split_counts.items():
    pct = (count / total_splits) * 100 if total_splits > 0 else 0
    print(f"  {f:24s}: {count:5d} splits ({pct:5.1f}%)")

# 3. SHAP TreeExplainer Output & Mathematical Direction Inspection
print("\n=== 3. SHAP MATHEMATICAL DIRECTION & VALUE DECOMPOSITION ===")
explainer = shap.TreeExplainer(m)
print(f"TreeExplainer expected_value (base value): {explainer.expected_value}")

# Load evaluation dataset & extract features
df_raw = build_constructed_evaluation_dataset(seed=42)
parsed = LogParser.parse_logs("\n".join(df_raw['log_line'].tolist()))
cleaned = DataCleaner.clean(parsed)
raw_feats = BehavioralFeatureExtractor.extract_features(cleaned)
preprocessed_df, _ = DataPreprocessor.preprocess(raw_feats)

X_eval = preprocessed_df[FEATURE_SCHEMA]
sv = explainer.shap_values(X_eval)

print(f"SHAP values shape on {len(X_eval)} evaluation samples: {sv.shape}")

# Verify additivity: sum(SHAP) + expected_value vs raw model score
scores = m.decision_function(X_eval)
raw_score_samples = m.score_samples(X_eval)
sum_shap = np.sum(sv, axis=1) + explainer.expected_value

print(f"Sample 0 (sum(SHAP) + base_val)  : {sum_shap[0]:.6f}")
print(f"Sample 0 score_samples(X)        : {raw_score_samples[0]:.6f}")
print(f"Sample 0 decision_function(X)    : {scores[0]:.6f}")
print(f"Difference max|sum_shap - score| : {np.max(np.abs(sum_shap - raw_score_samples)):.2e}")

# 4. Feature Utilization Metrics across 1,000 Evaluation Samples
print(f"\n=== 4. FEATURE UTILIZATION METRICS ACROSS {len(X_eval)} EVALUATION SAMPLES ===")
abs_sv = np.abs(sv)
mean_abs_shap = np.mean(abs_sv, axis=0)
non_zero_counts = np.sum(abs_sv > 1e-6, axis=0)
non_zero_pct = (non_zero_counts / len(X_eval)) * 100
max_abs_shap = np.max(abs_sv, axis=0)

summary_df = pd.DataFrame({
    'Feature': FEATURE_SCHEMA,
    'Tree Splits': [split_counts[f] for f in FEATURE_SCHEMA],
    'Tree Split %': [(split_counts[f] / total_splits) * 100 for f in FEATURE_SCHEMA],
    'Non-Zero SHAP Count': non_zero_counts,
    'Non-Zero SHAP %': non_zero_pct,
    'Mean |SHAP|': mean_abs_shap,
    'Max |SHAP|': max_abs_shap
})

print(summary_df.to_string(index=False))
