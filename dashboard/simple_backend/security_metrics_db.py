"""
Security Metrics Database
Tracks total requests, threats blocked, and threat vectors
"""
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import json

# Database path
DB_PATH = Path(__file__).parent / "security_metrics.db"


def init_security_metrics_db():
    """
    Initialize security metrics database with required tables.
    Creates empty tables ready to receive data.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Table for overall request metrics
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS request_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total_requests INTEGER NOT NULL DEFAULT 0,
            threats_blocked INTEGER NOT NULL DEFAULT 0,
            threats_flagged INTEGER NOT NULL DEFAULT 0,
            last_updated TIMESTAMP NOT NULL
        )
    ''')
    
    # Table for threat vector tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_vectors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_type VARCHAR(100) NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            last_detected TIMESTAMP,
            severity VARCHAR(20) DEFAULT 'medium',
            UNIQUE(threat_type)
        )
    ''')
    
    # Table for detailed security events (for historical tracking)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type VARCHAR(50) NOT NULL,
            threat_type VARCHAR(100),
            severity VARCHAR(20),
            blocked BOOLEAN NOT NULL DEFAULT 1,
            prompt_preview TEXT,
            source_ip VARCHAR(45),
            detected_at TIMESTAMP NOT NULL
        )
    ''')
    
    # Initialize request_metrics with zero values if empty
    cursor.execute("SELECT COUNT(*) FROM request_metrics")
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            INSERT INTO request_metrics (total_requests, threats_blocked, threats_flagged, last_updated)
            VALUES (0, 0, 0, ?)
        ''', (datetime.now(),))
    
    # Create indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_vectors_count ON threat_vectors(count DESC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_events_detected_at ON security_events(detected_at DESC)')
    
    conn.commit()
    conn.close()
    
    print(f"✅ Security metrics database initialized: {DB_PATH}")


def get_total_requests() -> int:
    """Get total number of requests processed"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT total_requests FROM request_metrics ORDER BY id DESC LIMIT 1")
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else 0


def get_threats_blocked() -> int:
    """Get total number of threats blocked"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT threats_blocked FROM request_metrics ORDER BY id DESC LIMIT 1")
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else 0


def get_top_threat_vector() -> Dict[str, any]:
    """
    Get the most common threat type.
    
    Returns:
        Dictionary with threat_type and count, or None if no data
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT threat_type, count, severity, last_detected
        FROM threat_vectors
        ORDER BY count DESC
        LIMIT 1
    ''')
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            "threat_type": result[0],
            "count": result[1],
            "severity": result[2],
            "last_detected": result[3]
        }
    return {
        "threat_type": "None",
        "count": 0,
        "severity": "low",
        "last_detected": None
    }


def get_all_threat_vectors() -> List[Dict[str, any]]:
    """Get all threat vectors sorted by count"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT threat_type, count, severity, last_detected
        FROM threat_vectors
        ORDER BY count DESC
    ''')
    results = cursor.fetchall()
    conn.close()
    
    return [
        {
            "threat_type": row[0],
            "count": row[1],
            "severity": row[2],
            "last_detected": row[3]
        }
        for row in results
    ]


def increment_total_requests():
    """Increment the total request counter"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE request_metrics
        SET total_requests = total_requests + 1,
            last_updated = ?
        WHERE id = (SELECT id FROM request_metrics ORDER BY id DESC LIMIT 1)
    ''', (datetime.now(),))
    conn.commit()
    conn.close()


def increment_threats_blocked():
    """Increment the threats blocked counter"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE request_metrics
        SET threats_blocked = threats_blocked + 1,
            last_updated = ?
        WHERE id = (SELECT id FROM request_metrics ORDER BY id DESC LIMIT 1)
    ''', (datetime.now(),))
    conn.commit()
    conn.close()


def record_threat_detection(threat_type: str, severity: str = "medium", blocked: bool = True):
    """
    Record a threat detection event.
    
    Args:
        threat_type: Type of threat detected (e.g., "DAN Attacks", "Jailbreak")
        severity: Severity level (low, medium, high, critical)
        blocked: Whether the threat was blocked
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Update or insert threat vector count
    cursor.execute('''
        INSERT INTO threat_vectors (threat_type, count, severity, last_detected)
        VALUES (?, 1, ?, ?)
        ON CONFLICT(threat_type) DO UPDATE SET
            count = count + 1,
            last_detected = ?,
            severity = ?
    ''', (threat_type, severity, datetime.now(), datetime.now(), severity))
    
    conn.commit()
    conn.close()
    
    # Increment counters
    increment_total_requests()
    if blocked:
        increment_threats_blocked()


def get_security_metrics_summary() -> Dict[str, any]:
    """
    Get complete security metrics summary.
    
    Returns:
        Dictionary with all metrics
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get request metrics
    cursor.execute("SELECT total_requests, threats_blocked, threats_flagged, last_updated FROM request_metrics ORDER BY id DESC LIMIT 1")
    metrics_row = cursor.fetchone()
    
    if metrics_row:
        total_requests = metrics_row[0]
        threats_blocked = metrics_row[1]
        threats_flagged = metrics_row[2]
        last_updated = metrics_row[3]
    else:
        total_requests = 0
        threats_blocked = 0
        threats_flagged = 0
        last_updated = None
    
    # Get top threat vector
    cursor.execute('''
        SELECT threat_type, count, severity
        FROM threat_vectors
        ORDER BY count DESC
        LIMIT 1
    ''')
    top_threat_row = cursor.fetchone()
    
    if top_threat_row:
        top_threat_vector = top_threat_row[0]
        top_threat_count = top_threat_row[1]
        top_threat_severity = top_threat_row[2]
    else:
        top_threat_vector = "None detected"
        top_threat_count = 0
        top_threat_severity = "low"
    
    # Get all threat vectors
    cursor.execute('''
        SELECT threat_type, count, severity, last_detected
        FROM threat_vectors
        ORDER BY count DESC
        LIMIT 10
    ''')
    threat_vectors = [
        {
            "threat_type": row[0],
            "count": row[1],
            "severity": row[2],
            "last_detected": row[3]
        }
        for row in cursor.fetchall()
    ]
    
    conn.close()
    
    # Calculate block rate
    block_rate = (threats_blocked / max(total_requests, 1)) * 100 if total_requests > 0 else 0
    
    return {
        "total_requests": total_requests,
        "threats_blocked": threats_blocked,
        "threats_flagged": threats_flagged,
        "block_rate": round(block_rate, 2),
        "top_threat_vector": {
            "name": top_threat_vector,
            "count": top_threat_count,
            "severity": top_threat_severity
        },
        "all_threat_vectors": threat_vectors,
        "last_updated": last_updated
    }


def reset_metrics():
    """Reset all metrics to zero (for testing)"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE request_metrics
        SET total_requests = 0,
            threats_blocked = 0,
            threats_flagged = 0,
            last_updated = ?
    ''', (datetime.now(),))
    
    cursor.execute('DELETE FROM threat_vectors')
    cursor.execute('DELETE FROM security_events')
    
    conn.commit()
    conn.close()
    
    print("✅ All security metrics reset to zero")


# Initialize database on module import
init_security_metrics_db()
