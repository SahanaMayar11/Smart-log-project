import sqlite3
import os
import json

DB_PATH = os.path.join(os.path.dirname(__file__), 'smartlog.db')

def get_db_connection():
    """Establishes connection to SQLite database with Row factory and non-blocking WAL concurrency."""
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 30000;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except Exception:
        pass
    return conn


def init_db():
    """Initializes database schema and populates default admin user."""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("PRAGMA journal_mode=WAL;")
    except Exception:
        pass

    # Table for Admin Authentication
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # Table for Uploaded File Metadata
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_logs INTEGER DEFAULT 0,
            normal_count INTEGER DEFAULT 0,
            anomaly_count INTEGER DEFAULT 0
        )
    ''')

    # Table for Parsed Server Logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS parsed_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            timestamp TEXT,
            hostname TEXT,
            service TEXT,
            log_level TEXT,
            event_type TEXT,
            message TEXT,
            FOREIGN KEY (file_id) REFERENCES uploaded_files (id)
        )
    ''')

    # Table for Behavioral Features (Exact 8 Features)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS extracted_features (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            log_id INTEGER,
            event_frequency REAL,
            sequence_length INTEGER,
            error_count INTEGER,
            error_pattern INTEGER,
            login_attempts INTEGER,
            failed_login_attempts INTEGER,
            warning_count INTEGER,
            unknown_events INTEGER,
            FOREIGN KEY (file_id) REFERENCES uploaded_files (id),
            FOREIGN KEY (log_id) REFERENCES parsed_logs (id)
        )
    ''')

    # Table for Isolation Forest Anomaly Detection Results
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS anomaly_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            log_id INTEGER,
            is_anomaly INTEGER,  -- 1 for Anomaly, 0 for Normal
            anomaly_score REAL,
            severity TEXT,       -- Normal, Warning, Anomaly
            FOREIGN KEY (file_id) REFERENCES uploaded_files (id),
            FOREIGN KEY (log_id) REFERENCES parsed_logs (id)
        )
    ''')

    # Table for SHAP Explainability Outputs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shap_explanations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            log_id INTEGER,
            feature_contributions TEXT, -- JSON string of feature SHAP values
            top_reason TEXT,
            natural_explanation TEXT,
            FOREIGN KEY (file_id) REFERENCES uploaded_files (id),
            FOREIGN KEY (log_id) REFERENCES parsed_logs (id)
        )
    ''')

    # Insert default admin user if not exists
    cursor.execute("SELECT id FROM admin_users WHERE username = 'admin'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO admin_users (username, password) VALUES ('admin', 'admin123')")

    # Create performance indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_parsed_file ON parsed_logs(file_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_feat_file_log ON extracted_features(file_id, log_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_feat_log ON extracted_features(log_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomaly_file_log ON anomaly_results(file_id, log_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomaly_log ON anomaly_results(log_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_shap_file_log ON shap_explanations(file_id, log_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_shap_log ON shap_explanations(log_id)")

    # Ensure Windows Event specific columns exist
    new_columns = [
        ("channel", "TEXT"),
        ("event_id", "INTEGER"),
        ("record_id", "INTEGER"),
        ("application", "TEXT"),
        ("application_name", "TEXT"),
        ("process", "TEXT"),
        ("process_name", "TEXT"),
        ("pid", "TEXT"),
        ("process_id", "TEXT"),
        ("parent_pid", "TEXT"),
        ("parent_process", "TEXT"),
        ("parent_process_name", "TEXT"),
        ("parent_application", "TEXT"),
        ("creator_pid", "TEXT"),
        ("creator_process", "TEXT"),
        ("user", "TEXT"),
        ("domain", "TEXT"),
        ("computer", "TEXT"),
        ("action", "TEXT"),
        ("description", "TEXT"),
        ("raw_process_path", "TEXT"),
        ("executable_path", "TEXT"),
        ("provider", "TEXT"),
        ("source", "TEXT"),
        ("source_label", "TEXT"),
        ("device", "TEXT"),
        ("time", "TEXT"),
        ("status", "TEXT"),
        ("unique_event_key", "TEXT"),
        ("raw_payload", "TEXT")
    ]
    for col_name, col_type in new_columns:
        try:
            cursor.execute(f"ALTER TABLE parsed_logs ADD COLUMN {col_name} {col_type}")
        except Exception:
            pass

    # Ensure SHAP human-readable explanation columns exist
    for col_name in [
        'what_happened', 'why_suspicious', 'recommended_action', 'top_3_human_reasons',
        'application_source', 'what_it_means', 'why_flagged', 'evidence',
        'risk_assessment', 'limitations_uncertainty', 'technical_details'
    ]:
        try:
            cursor.execute(f"ALTER TABLE shap_explanations ADD COLUMN {col_name} TEXT")
        except Exception:
            pass

    # Ensure simulation tracking columns exist
    sim_columns = [
        ("uploaded_files", "is_simulated", "INTEGER DEFAULT 0"),
        ("uploaded_files", "simulation_scenario", "TEXT"),
        ("parsed_logs", "is_simulated", "INTEGER DEFAULT 0"),
        ("parsed_logs", "simulation_scenario", "TEXT"),
        ("anomaly_results", "is_simulated", "INTEGER DEFAULT 0"),
        ("anomaly_results", "simulation_scenario", "TEXT"),
        ("anomaly_results", "consensus_state", "TEXT"),
        ("anomaly_results", "consensus_agreement", "INTEGER"),
        ("shap_explanations", "is_simulated", "INTEGER DEFAULT 0")
    ]
    for table_name, col_name, col_type in sim_columns:
        try:
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")
        except Exception:
            pass

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_parsed_unique_key ON parsed_logs(unique_event_key)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_parsed_timestamp ON parsed_logs(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_parsed_ts_id ON parsed_logs(timestamp DESC, id DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_parsed_sim ON parsed_logs(is_simulated)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_sim ON uploaded_files(is_simulated)")

    conn.commit()
    conn.close()
    print("Database initialized successfully.")


if __name__ == '__main__':
    init_db()
