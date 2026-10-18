# Objective Implementation: Demonstration & Verification Suite
## Verification of Official Project Objectives 1 & 2

This self-contained folder demonstrates the end-to-end implementation of the two official project objectives for **Smart-Log**.

---

### Project Objectives

- **Objective 1**: To preprocess the dataset by cleaning missing and invalid values and selecting relevant features, ensuring structured and anomaly-ready data.
- **Objective 2**: To design and develop a behavior-based anomaly detection system that implements the Isolation Forest algorithm for anomaly detection and validate the results using One-Class SVM to improve reliability.

---

### Folder Structure

```
objective_implementation/
│
├── README.md                          # Comprehensive guide for teammates & evaluators
├── requirements.txt                   # Minimal dependencies (numpy, pandas, scikit-learn, joblib)
├── run_demo.py                        # Master 1-click demonstration script
│
├── data/
│   └── data_loader.py                 # Loads real HDFS dataset and sample log streams (leakage-free)
│
├── preprocessing/
│   ├── cleaner.py                     # Missing/invalid value cleaning & DataPreprocessor
│   └── feature_extractor.py           # 8-feature behavioral sliding-window extractor
│
├── models/
│   ├── isolation_forest.py            # Primary behavior-based Isolation Forest detector
│   └── one_class_svm.py               # Secondary One-Class SVM validator & consensus
│
├── evaluation/
│   └── evaluate.py                    # Empirical evaluation metrics & confusion matrix
│
└── results/
    ├── preprocessing_results.csv      # Real preprocessed 8-feature matrix
    ├── anomaly_results.csv            # Real predictions, scores, and consensus
    └── evaluation_results.json        # Machine-readable evaluation report
```

---

### How to Run

Execute the master demonstration from the project root or from inside `objective_implementation/`:

```powershell
# From project root:
python objective_implementation/run_demo.py

# Or navigate inside the folder:
cd objective_implementation
python run_demo.py
```

---

### Pipeline Flow

```
1. Input Data / Log Stream
          ↓
2. Data Cleaning & Sanitization (Missing NaN, Infinite inf, Negative bounding)
          ↓
3. 8 Canonical Behavioral Feature Extraction
   (event_frequency, sequence_length, error_count, error_pattern,
    login_attempts, failed_login_attempts, warning_count, unknown_events)
          ↓
4. Preprocessing & Leakage Protection (Fitted medians derived from X_train only)
          ↓
   ┌──────┴──────┐
   ↓             ↓
5. Primary Model: Isolation Forest        6. Secondary Model: One-Class SVM
   (n_estimators=100, contam=0.0293)         (RBF kernel, nu=0.03)
   → Continuous Anomaly Score (0.00-1.00)     → Validation Prediction
   └──────┬──────┘
          ↓
7. Consensus State Classification & Empirical Metrics
   (Consensus Normal, Consensus Anomaly, Model Disagreement)
```

---

### Strict Avoidance of Data Leakage

- Ground-truth anomaly labels $y$ are **strictly withheld during training**.
- Both `IsolationForest.fit()` and `OneClassSVM.fit()` receive purely unlabeled feature vectors $X_{	ext{train}}$.
- Labels $y_{	ext{test}}$ are used exclusively in `evaluation/evaluate.py` to calculate post-prediction test metrics (Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR, Confusion Matrix).
