# Data Cleaner & Preprocessing Module for Objective 1
import numpy as np
import pandas as pd

FEATURE_SCHEMA = [
    'event_frequency',
    'sequence_length',
    'error_count',
    'error_pattern',
    'login_attempts',
    'failed_login_attempts',
    'warning_count',
    'unknown_events'
]


class PreprocessingPipeline:
    """
    Objective 1 Implementation:
    Cleans missing and invalid values, enforces schema consistency,
    and produces structured, anomaly-ready numerical data without data leakage.
    """

    @classmethod
    def clean_and_preprocess(cls, feature_df, fit_medians=None, fit_max_finite=None):
        if feature_df is None or len(feature_df) == 0:
            raise ValueError("Input feature DataFrame is empty or None.")

        df = feature_df.copy()
        input_records = len(df)
        missing_count = 0
        invalid_count = 0
        computed_medians = {}
        computed_max_finite = {}

        # 1. Enforce 8 canonical feature columns
        for col in FEATURE_SCHEMA:
            if col not in df.columns:
                df[col] = np.nan
                missing_count += input_records

        df_feats = df[FEATURE_SCHEMA].copy()

        # 2. Missing value detection and median imputation (leakage protected)
        for col in FEATURE_SCHEMA:
            non_num_mask = pd.to_numeric(df_feats[col], errors='coerce').isna()
            null_mask = df_feats[col].isna()
            col_missing = (null_mask | non_num_mask)
            num_missing = int(col_missing.sum())

            if fit_medians is not None and col in fit_medians:
                med_val = float(fit_medians[col])
            else:
                valid_vals = pd.to_numeric(df_feats.loc[~col_missing, col], errors='coerce')
                med_val = float(valid_vals.median()) if len(valid_vals) > 0 and not np.isnan(valid_vals.median()) else 0.0
            computed_medians[col] = med_val

            if num_missing > 0:
                missing_count += num_missing
                df_feats.loc[col_missing, col] = med_val

            df_feats[col] = pd.to_numeric(df_feats[col], errors='coerce').fillna(0.0)

        # 3. Invalid and Infinite value handling with train-isolated bounds
        for col in FEATURE_SCHEMA:
            col_vals = df_feats[col].values

            # Infinite values (inf, -inf)
            inf_mask = np.isinf(col_vals)
            finite_vals = col_vals[~inf_mask]
            if fit_max_finite is not None and col in fit_max_finite:
                max_finite = float(fit_max_finite[col])
            else:
                max_finite = float(np.max(finite_vals)) if len(finite_vals) > 0 else 100.0
            computed_max_finite[col] = max_finite

            if np.any(inf_mask):
                invalid_count += int(np.sum(inf_mask))
                col_vals[inf_mask] = max_finite

            # Negative values (all features represent non-negative metrics)
            neg_mask = (col_vals < 0)
            if np.any(neg_mask):
                invalid_count += int(np.sum(neg_mask))
                col_vals[neg_mask] = 0.0

            # Error pattern boundary [0, 4]
            if col == 'error_pattern':
                out_of_bounds = (col_vals > 4)
                if np.any(out_of_bounds):
                    invalid_count += int(np.sum(out_of_bounds))
                    col_vals[out_of_bounds] = 4.0

            df_feats[col] = col_vals

        # 4. Strict Post-Condition Validation
        has_nan = bool(df_feats[FEATURE_SCHEMA].isna().any().any())
        has_inf = bool(np.isinf(df_feats[FEATURE_SCHEMA].values).any())

        if has_nan or has_inf:
            raise ValueError("Preprocessing failed: NaN or Inf remaining in feature matrix.")

        stats = {
            'input_records': input_records,
            'missing_values_detected': missing_count,
            'missing_values_cleaned': missing_count,
            'invalid_values_detected': invalid_count,
            'invalid_values_cleaned': invalid_count,
            'final_records': len(df_feats),
            'selected_features': FEATURE_SCHEMA,
            'feature_shape': df_feats[FEATURE_SCHEMA].shape,
            'fitted_medians': computed_medians,
            'fitted_max_finite': computed_max_finite
        }

        return df_feats[FEATURE_SCHEMA], stats
