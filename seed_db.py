#!/usr/bin/env python3
"""
CLI script to seed or reset the database for Password Breach Monitoring.
Supports both MySQL / MariaDB (Database `Case-Study`) and SQLite (File `pbm_database.db`).

Usage:
    python seed_db.py                 (Seeds active engine if empty)
    python seed_db.py --reset         (Force re-seed all tables)
    python seed_db.py --mysql         (Target MySQL / MariaDB `Case-Study` database)
    python seed_db.py --sqlite        (Target SQLite `pbm_database.db`)
    python seed_db.py --mysql --host localhost --user root --password mypass
"""

import sys
import os
import argparse
from app.db import init_db, get_db_info

def main():
    parser = argparse.ArgumentParser(description="PBM Database Seeding & Setup Utility")
    parser.add_argument("--reset", "--force", action="store_true", help="Force wipe and reseed all records")
    parser.add_argument("--mysql", action="store_true", help="Explicitly target MySQL / MariaDB")
    parser.add_argument("--sqlite", action="store_true", help="Explicitly target SQLite")
    parser.add_argument("--host", type=str, default=None, help="MySQL Host (default: localhost)")
    parser.add_argument("--port", type=int, default=None, help="MySQL Port (default: 3306)")
    parser.add_argument("--user", type=str, default=None, help="MySQL User (default: root)")
    parser.add_argument("--password", type=str, default=None, help="MySQL Password")
    parser.add_argument("--db", type=str, default=None, help="MySQL Database Name (default: Case-Study)")

    args = parser.parse_args()

    if args.host:
        os.environ["MYSQL_HOST"] = args.host
    if args.port:
        os.environ["MYSQL_PORT"] = str(args.port)
    if args.user:
        os.environ["MYSQL_USER"] = args.user
    if args.password is not None:
        os.environ["MYSQL_PASSWORD"] = args.password
    if args.db:
        os.environ["MYSQL_DB"] = args.db

    target_engine = None
    if args.mysql:
        target_engine = "mysql"
        os.environ["DB_ENGINE"] = "mysql"
    elif args.sqlite:
        target_engine = "sqlite"
        os.environ["DB_ENGINE"] = "sqlite"

    print("==================================================================")
    print("  Password Breach Monitoring (PBM) - Database Seeder")
    print("==================================================================")
    
    info = get_db_info()
    print(f"Target Engine : {target_engine or info['engine']}")
    if (target_engine or info['engine']) == "mysql":
        print(f"MySQL Host    : {info['mysql_host']}:{info['mysql_port']}")
        print(f"MySQL User    : {info['mysql_user']}")
        print(f"MySQL Database: `{info['mysql_database']}`")
    else:
        print(f"SQLite File   : {info['sqlite_path']}")
    print(f"Force Reseed  : {args.reset}")
    print("------------------------------------------------------------------")

    try:
        init_db(force_reseed=args.reset, target_engine=target_engine)
        print("\n[SUCCESS] Database initialization completed successfully.")
    except Exception as e:
        print(f"\n[ERROR] Seeding failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
