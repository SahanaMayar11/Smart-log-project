# Smart-Log Backend ML Pipeline & Training Guide

This directory contains the Python Flask REST API backend, SQLite database setup, and the Isolation Forest ML model training pipeline for **Smart-Log: Automated Syslog Anomaly Detection for Server Security**.

---

## 🛠️ Model Training & Retraining Instructions

### 1. Training the Model
To manually train or retrain the Isolation Forest machine learning model on a log dataset:

```bash
cd backend
python train_model.py
```

### 2. Training Workflow Execution
When `python train_model.py` is executed, it performs:
1. **Dataset Loading**: Reads log dataset from `backend/sample_logs/training_dataset.log` (or `server_syslog.log`).
2. **Log Parsing**: Extracts `Timestamp`, `Hostname`, `Service`, `Log Level`, `Event Type`, `Message`.
3. **Data Cleaning**: Strips whitespace and standardizes missing values.
4. **Behavioral Feature Extraction**: Calculates exact 8 behavioral features (*Event Frequency, Sequence Length, Error Count, Error Pattern, Login Attempts, Failed Login Attempts, Warning Count, Unknown Events*).
5. **Isolation Forest Model Training**: Fits `scikit-learn` Isolation Forest model.
6. **Model Serialization**: Saves trained model artifact to `backend/models/isolation_forest_model.pkl` using `joblib`.

### 3. Automatic Model Loading in Flask API
- When the Flask backend (`app.py`) starts, it automatically checks if `backend/models/isolation_forest_model.pkl` exists.
- If present, it loads the saved model for fast inference without retraining.
- If missing, it automatically invokes `train_model.py` once, saves the model file, and loads it.

---

## 📡 REST API Endpoints

- `POST /api/auth/login`: Admin authentication.
- `POST /api/system-logs/analyze`: Ingests and analyzes historical Windows Event Logs (1h, 6h, 24h, 7d).
- `GET /api/system-logs/live`: Streams live near-real-time buffered Windows system telemetry events.
- `GET /api/dashboard/stats`: Returns KPI metrics and chart datasets.
- `GET /api/logs/parsed`: Filterable and paginated parsed log table.
- `GET /api/features`: Matrix of 8 extracted behavioral features.
- `GET /api/detection/results`: Isolation Forest predictions and anomaly scores.
- `GET /api/shap/explanations`: SHAP feature importance rankings and natural language explanation cards.
- `GET /api/reports/summary`: PDF and CSV summary report metrics.
