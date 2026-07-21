import sqlite3
import os
import json
import math
from datetime import datetime

def sanitize_float(val, default=0.0):
    try:
        fval = float(val)
        if math.isnan(fval) or math.isinf(fval):
            return default
        return fval
    except (ValueError, TypeError):
        return default

def sanitize_shap_explanation(shap_explanation):
    if not isinstance(shap_explanation, list):
        return shap_explanation
    cleaned = []
    for item in shap_explanation:
        if isinstance(item, dict):
            c_item = item.copy()
            impact = item.get("impact", 0.0)
            c_item["impact"] = sanitize_float(impact)
            cleaned.append(c_item)
        else:
            cleaned.append(item)
    return cleaned

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs", "database.sqlite"))

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Create prediction history table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        mode TEXT,
        file_row_number INTEGER,
        src_ip TEXT,
        dst_ip TEXT,
        protocol TEXT,
        dst_port INTEGER,
        prediction INTEGER,
        confidence REAL,
        attack_type TEXT,
        if_score REAL,
        ensemble_score REAL,
        shap_explanation TEXT
    )
    """)

    # Check if file_row_number column exists in history table, if not add it (migration for existing db files)
    try:
        cursor.execute("SELECT file_row_number FROM history LIMIT 1")
    except sqlite3.OperationalError:
        try:
            cursor.execute("ALTER TABLE history ADD COLUMN file_row_number INTEGER")
        except Exception:
            pass

    # Migration: older databases named the model score column 'xgb_prob'
    try:
        cursor.execute("SELECT ensemble_score FROM history LIMIT 1")
    except sqlite3.OperationalError:
        try:
            cursor.execute("ALTER TABLE history RENAME COLUMN xgb_prob TO ensemble_score")
        except Exception:
            try:
                cursor.execute("ALTER TABLE history ADD COLUMN ensemble_score REAL")
            except Exception:
                pass
    
    # 2. Create settings table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)
    
    # 3. Create logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        level TEXT,
        message TEXT
    )
    """)
    
    # Insert default settings if they don't exist
    default_settings = {
        "context_window": "30",
        "model_selection": "Hybrid Model",
        "confidence_threshold": "0.5",
        "packet_capture_interface": "",
        "auto_refresh": "true",
        "dark_mode": "true"
    }
    
    for key, val in default_settings.items():
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, val))
        
    conn.commit()
    conn.close()
    add_log("INFO", "Database initialized successfully.")

def add_log(level, message):
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO logs (timestamp, level, message) VALUES (?, ?, ?)", (timestamp, level, message))
    conn.commit()
    conn.close()

def get_logs(limit=100):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, level, message FROM logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_settings():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    rows = cursor.fetchall()
    conn.close()
    return {row["key"]: row["value"] for row in rows}

def save_setting(key, value):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()
    add_log("INFO", f"Setting '{key}' updated to '{value}'.")

def get_setting(key, default=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row["value"]
    return default

def add_prediction(mode, src_ip, dst_ip, protocol, dst_port, prediction, confidence, attack_type, if_score, ensemble_score, shap_explanation, file_row_number=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # shap_explanation is expected to be a list/dict, dump to json string
    clean_shap = sanitize_shap_explanation(shap_explanation)
    shap_str = json.dumps(clean_shap) if isinstance(clean_shap, (list, dict)) else str(clean_shap)

    clean_confidence = sanitize_float(confidence)
    clean_if_score = sanitize_float(if_score)
    clean_ensemble_score = sanitize_float(ensemble_score)

    cursor.execute("""
    INSERT INTO history (timestamp, mode, file_row_number, src_ip, dst_ip, protocol, dst_port, prediction, confidence, attack_type, if_score, ensemble_score, shap_explanation)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, mode, file_row_number, src_ip, dst_ip, protocol, dst_port, int(prediction), clean_confidence, attack_type, clean_if_score, clean_ensemble_score, shap_str))
    
    conn.commit()
    conn.close()

def add_predictions_batch(predictions: list):
    """
    Inserts a list of predictions in a single SQLite transaction for massive speedups.
    Each item in predictions is a dictionary with:
    'mode', 'src_ip', 'dst_ip', 'protocol', 'dst_port', 'prediction', 'confidence', 'attack_type', 'if_score', 'ensemble_score', 'shap_explanation', 'file_row_number'
    """
    if not predictions:
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    insert_data = []
    for p in predictions:
        shap_explanation = p.get("shap_explanation", [])
        clean_shap = sanitize_shap_explanation(shap_explanation)
        shap_str = json.dumps(clean_shap) if isinstance(clean_shap, (list, dict)) else str(clean_shap)
        insert_data.append((
            timestamp,
            p["mode"],
            p.get("file_row_number"),
            p["src_ip"],
            p["dst_ip"],
            p["protocol"],
            int(p["dst_port"]),
            int(p["prediction"]),
            sanitize_float(p["confidence"]),
            p["attack_type"],
            sanitize_float(p["if_score"]),
            sanitize_float(p["ensemble_score"]),
            shap_str
        ))

    cursor.executemany("""
    INSERT INTO history (timestamp, mode, file_row_number, src_ip, dst_ip, protocol, dst_port, prediction, confidence, attack_type, if_score, ensemble_score, shap_explanation)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, insert_data)
    
    conn.commit()
    conn.close()

def get_history(search=None, mode=None, prediction=None, protocol=None, limit=100, offset=0, sort_by="timestamp", sort_order="DESC"):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM history WHERE 1=1"
    params = []
    
    if search:
        query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR attack_type LIKE ?)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param])
        
    if mode:
        query += " AND mode = ?"
        params.append(mode)
        
    if prediction is not None:
        query += " AND prediction = ?"
        params.append(int(prediction))
        
    if protocol:
        query += " AND protocol = ?"
        params.append(protocol)
        
    # Guard against SQL injection in sorting fields since they can't be parameterized directly
    allowed_sort_cols = ["timestamp", "mode", "file_row_number", "src_ip", "dst_ip", "protocol", "dst_port", "prediction", "confidence", "attack_type"]
    if sort_by not in allowed_sort_cols:
        sort_by = "timestamp"
    if sort_order.upper() not in ["ASC", "DESC"]:
        sort_order = "DESC"
        
    query += f" ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    # Get total count for pagination
    count_query = "SELECT COUNT(*) as count FROM history WHERE 1=1"
    count_params = []
    if search:
        count_query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR attack_type LIKE ?)"
        count_params.extend([search_param, search_param, search_param])
    if mode:
        count_query += " AND mode = ?"
        count_params.append(mode)
    if prediction is not None:
        count_query += " AND prediction = ?"
        count_params.append(int(prediction))
    if protocol:
        count_query += " AND protocol = ?"
        count_params.append(protocol)
        
    cursor.execute(count_query, count_params)
    total_count = cursor.fetchone()["count"]
    
    conn.close()
    
    results = []
    for row in rows:
        r = dict(row)
        try:
            r["shap_explanation"] = json.loads(r["shap_explanation"])
        except Exception:
            pass
        results.append(r)
        
    return results, total_count

def get_history_stats(mode=None):
    """
    Computes capturing time interval (start, end, duration) and statistical summary 
    for history data. Optional mode filter ('Online', 'Offline', etc.).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    where_clause = ""
    params = []
    if mode:
        where_clause = " WHERE mode = ?"
        params.append(mode)
        
    query = f"""
    SELECT 
        COUNT(*) as total_records,
        MIN(timestamp) as first_captured,
        MAX(timestamp) as latest_captured,
        SUM(CASE WHEN prediction = 1 THEN 1 ELSE 0 END) as anomaly_count,
        SUM(CASE WHEN prediction = 0 THEN 1 ELSE 0 END) as benign_count,
        SUM(CASE WHEN mode = 'Online' THEN 1 ELSE 0 END) as online_count,
        SUM(CASE WHEN mode = 'Offline' THEN 1 ELSE 0 END) as offline_count
    FROM history {where_clause}
    """
    cursor.execute(query, params)
    row = cursor.fetchone()
    conn.close()
    
    total_records = row["total_records"] if row else 0
    first_captured = row["first_captured"] if row and row["first_captured"] else None
    latest_captured = row["latest_captured"] if row and row["latest_captured"] else None
    anomaly_count = row["anomaly_count"] if row and row["anomaly_count"] is not None else 0
    benign_count = row["benign_count"] if row and row["benign_count"] is not None else 0
    online_count = row["online_count"] if row and row["online_count"] is not None else 0
    offline_count = row["offline_count"] if row and row["offline_count"] is not None else 0
    
    interval_seconds = 0
    formatted_duration = "N/A"
    
    if first_captured and latest_captured:
        try:
            from datetime import datetime
            fmt = "%Y-%m-%d %H:%M:%S"
            t1 = datetime.strptime(first_captured, fmt)
            t2 = datetime.strptime(latest_captured, fmt)
            delta = t2 - t1
            interval_seconds = max(int(delta.total_seconds()), 0)
            
            hours, remainder = divmod(interval_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            days, hours = divmod(hours, 24)
            
            parts = []
            if days > 0:
                parts.append(f"{days}d")
            if hours > 0:
                parts.append(f"{hours}h")
            if minutes > 0 or (days == 0 and hours == 0 and seconds == 0):
                parts.append(f"{minutes}m")
            if seconds > 0 or len(parts) == 0:
                parts.append(f"{seconds}s")
            
            formatted_duration = " ".join(parts)
        except Exception:
            formatted_duration = "N/A"
            
    return {
        "total_records": total_records,
        "first_captured": first_captured or "N/A",
        "latest_captured": latest_captured or "N/A",
        "interval_seconds": interval_seconds,
        "formatted_duration": formatted_duration,
        "anomaly_count": anomaly_count,
        "benign_count": benign_count,
        "online_count": online_count,
        "offline_count": offline_count
    }

