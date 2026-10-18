import json
import os
import re

from ml_engine import (
    DataCleaner,
    BehavioralFeatureExtractor,
    DataPreprocessor
)


# ---------------------------------------------------------
# 1. Load real Windows Event Logs
# ---------------------------------------------------------

input_path = os.path.join(
    os.environ["USERPROFILE"],
    "Documents",
    "SmartLogData",
    "windows_training_raw.json"
)

output_path = os.path.join(
    os.environ["USERPROFILE"],
    "Documents",
    "SmartLogData",
    "windows_training_features.json"
)

print("Loading:", input_path)

with open(input_path, "r", encoding="utf-8") as f:
    data = json.load(f)


# If only one JSON object exists, convert it to a list
if isinstance(data, dict):
    data = [data]

print("Raw Windows log records:", len(data))


# ---------------------------------------------------------
# 2. Convert Windows Event Logs into Smart-Log format
# ---------------------------------------------------------

level_mapping = {
    "Information": "INFO",
    "Warning": "WARN",
    "Error": "ERROR",
    "Critical": "ERROR",
    "Verbose": "DEBUG"
}

logs = []

for i, event in enumerate(data):

    message = str(event.get("Message", "") or "")
    provider = str(event.get("ProviderName", "system") or "system")
    level = str(event.get("LevelDisplayName", "") or "")

    message_upper = message.upper()

    # Determine event type
    if re.search(
        r"login|logon|authentication|password|security|failed",
        message,
        re.IGNORECASE
    ):
        event_type = "AUTHENTICATION"

    elif "UNKNOWN_EVENT" in message_upper:
        event_type = "UNKNOWN_EVENT"

    else:
        event_type = "SYSTEM_EVENT"

    logs.append({
        "log_id": i + 1,
        "timestamp": str(event.get("TimeCreated", "")),
        "hostname": "Windows-PC",
        "service": provider,
        "log_level": level_mapping.get(level, "DEBUG"),
        "event_type": event_type,
        "message": message
    })


# ---------------------------------------------------------
# 3. Clean logs
# ---------------------------------------------------------

cleaned_logs = DataCleaner.clean(logs)

print("Cleaned records:", len(cleaned_logs))


# ---------------------------------------------------------
# 4. Extract the exact 8 behavioral features
# ---------------------------------------------------------

features = BehavioralFeatureExtractor.extract_features(
    cleaned_logs
)

print("Feature records:", len(features))


# ---------------------------------------------------------
# 5. Preprocess and validate
# ---------------------------------------------------------

processed_features, stats = DataPreprocessor.preprocess(
    features
)


# ---------------------------------------------------------
# 6. Save training features
# ---------------------------------------------------------

processed_features.to_json(
    output_path,
    orient="records",
    indent=2
)


# ---------------------------------------------------------
# 7. Display results
# ---------------------------------------------------------

print()
print("=" * 60)
print("WINDOWS TRAINING DATA PREPARATION COMPLETE")
print("=" * 60)

print("Training records:", len(processed_features))

print()
print("Feature columns:")

for column in processed_features.columns:
    print(" -", column)

print()
print("Preprocessing statistics:")
print(stats)

print()
print("Saved training dataset:")
print(output_path)

print("=" * 60)