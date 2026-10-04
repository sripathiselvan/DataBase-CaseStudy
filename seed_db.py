#!/usr/bin/env python3
"""
CLI script to seed or reset the SQLite database for Password Breach Monitoring.
Usage:
    python seed_db.py          (Initialize/seed if empty)
    python seed_db.py --reset  (Force reset and re-seed 120+ records)
"""

import sys
from app.db import init_db

if __name__ == "__main__":
    force_reset = "--reset" in sys.argv
    print(f"Initializing database... (force_reset={force_reset})")
    init_db(force_reseed=force_reset)
    print("Database seeding completed.")
