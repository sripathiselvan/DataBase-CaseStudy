"""
Database module for Password Breach Monitoring (PBM).
Handles SQLite schema creation, connection management, queries, and data seeding.
"""

import os
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "pbm_database.db"

def get_db_connection(read_only=False):
    """
    Returns a sqlite3 Connection object.
    If read_only is True, opens connection in read-only mode using SQLite URI.
    """
    if read_only:
        # Connect in read-only mode to enforce engine-level security
        uri = f"file:{DB_PATH.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(force_reseed=False):
    """
    Creates database tables if they do not exist and seeds initial data if empty.
    """
    db_existed = DB_PATH.exists()
    
    conn = get_db_connection(read_only=False)
    cursor = conn.cursor()

    # Create breaches table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS breaches (
            id TEXT PRIMARY KEY,
            breach_name TEXT NOT NULL,
            organization TEXT NOT NULL,
            industry TEXT NOT NULL,
            breach_date TEXT NOT NULL,
            discovery_date TEXT NOT NULL,
            affected_records INTEGER NOT NULL,
            severity TEXT NOT NULL,
            breach_type TEXT NOT NULL,
            attack_vector TEXT NOT NULL,
            data_exposed TEXT NOT NULL,
            root_cause TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    # Create case_studies table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_studies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            breach_id TEXT NOT NULL,
            title TEXT NOT NULL,
            subtitle TEXT NOT NULL,
            date TEXT NOT NULL,
            severity TEXT NOT NULL,
            executive_summary TEXT NOT NULL,
            timeline_json TEXT NOT NULL,
            response TEXT NOT NULL,
            attack_vector_tags TEXT NOT NULL,
            root_cause TEXT NOT NULL,
            data_exposed_tags TEXT NOT NULL,
            impact_metrics TEXT NOT NULL,
            lessons_learned TEXT NOT NULL,
            FOREIGN KEY (breach_id) REFERENCES breaches (id)
        )
    """)

    conn.commit()

    # Check if breaches table is empty or if reseed is requested
    cursor.execute("SELECT COUNT(*) FROM breaches")
    count = cursor.fetchone()[0]

    if count == 0 or force_reseed:
        from data.seed_data import generate_breach_records, CASE_STUDIES
        
        if force_reseed:
            cursor.execute("DELETE FROM case_studies")
            cursor.execute("DELETE FROM breaches")

        breaches = generate_breach_records(total_count=120)
        cursor.executemany("""
            INSERT INTO breaches (
                id, breach_name, organization, industry, breach_date,
                discovery_date, affected_records, severity, breach_type,
                attack_vector, data_exposed, root_cause, status
            ) VALUES (
                :id, :breach_name, :organization, :industry, :breach_date,
                :discovery_date, :affected_records, :severity, :breach_type,
                :attack_vector, :data_exposed, :root_cause, :status
            )
        """, breaches)

        for cs in CASE_STUDIES:
            cursor.execute("""
                INSERT INTO case_studies (
                    breach_id, title, subtitle, date, severity,
                    executive_summary, timeline_json, response,
                    attack_vector_tags, root_cause, data_exposed_tags,
                    impact_metrics, lessons_learned
                ) VALUES (
                    :breach_id, :title, :subtitle, :date, :severity,
                    :executive_summary, :timeline_json, :response,
                    :attack_vector_tags, :root_cause, :data_exposed_tags,
                    :impact_metrics, :lessons_learned
                )
            """, cs)

        conn.commit()
        print(f"Successfully initialized and seeded database with {len(breaches)} breach records.")

    conn.close()
