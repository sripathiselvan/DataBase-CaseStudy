# Password Breach Monitoring (PBM) — MySQL, MariaDB & SQLite Platform

A full-stack cybersecurity threat intelligence, breach analytics, and executive case-study platform built with **Python**, **Flask**, and **MySQL / MariaDB** (with seamless **SQLite** fallback).

The platform delivers **100% real and authentic breach intelligence data**, a consolidated **executive summary report** summarizing all database data in a crisp white theme, interactive analytics, and a sandboxed read-only SQL Explorer.

---

## Key Features & Highlights

1. **Clean Modern White Theme**:
   - High-contrast, clean light-themed UI designed for clarity, readability, and professional reporting.
   - Pure white executive document presentation for case studies and reports (print- and PDF-ready).

2. **100% Real & Authentic Breach Intelligence**:
   - Zero synthetic/fake data.
   - Sourced directly from official regulatory enforcement orders (US FTC, SEC, DOJ), CISA advisories, Mandiant threat intelligence, and published corporate post-mortems.
   - Fully cited in [`DATA_SOURCES.txt`](file:///home/eclipse/Projects/Case-Study/DATA_SOURCES.txt).

3. **Consolidated Executive Summarized Report (All Data)**:
   - Compiles a comprehensive executive briefing summarizing all 80+ documented incidents and case studies across the database.
   - Includes: *Macro Threat Synopsis, Exposure Scorecard, Targeted Industry Risk Ranking, Attack Vector Taxonomy, Chronological Threat Eras, Landmark Case Studies Forensic Summary, NIST Cybersecurity Framework (CSF 2.0) Matrix, Strategic CISO Directives, and Regulatory Citations*.
   - Instant export options: **Print / Save as PDF**, **Download Markdown (.md)**, **Download Plain Text (.txt)**, **Export JSON**, and **Copy to Clipboard**.

4. **Dual Database Engine (MySQL / MariaDB & SQLite)**:
   - Primary target database: **`Case-Study`** on **MySQL 5.7+ / 8.0+** or **MariaDB 10.3+**.
   - Includes standalone SQL dump file [`database.sql`](file:///home/eclipse/Projects/Case-Study/database.sql) for 1-click import via `mysql` / `mariadb` cmd.
   - Seamless fallback to local single-file database `pbm_database.db` if running standalone without a MySQL daemon.

5. **Interactive Read-Only SQL Explorer**:
   - Sandboxed query builder with prebuilt queries, visual table previews, and execution security validation.

---

## Directory Structure

```
Case-Study/
├── app/
│   ├── __init__.py          # Flask Application Factory & Route Registration
│   ├── api.py               # REST API Blueprint (Breaches, Case Studies, Reports, Analytics, SQL Runner)
│   ├── db.py                # Dual MySQL / MariaDB & SQLite Database Interface & Query Wrapper
│   └── sql_validator.py     # Safe Read-Only SELECT Query Security Validator
├── data/
│   └── seed_data.py         # 80+ authentic historical breach records & 12 in-depth case studies
├── static/
│   ├── css/
│   │   └── style.css        # Clean White / Light Theme CSS design system
│   └── js/
│       └── app.js           # Frontend client with report generator & async API integration
├── templates/
│   └── index.html           # Modern semantic HTML5 dashboard template
├── tests/
│   └── test_api.py          # Automated PyUnit test suite validating 14 test specs
├── database.sql             # MySQL / MariaDB standalone SQL schema and data import script
├── DATA_SOURCES.txt         # Comprehensive verified citations and regulatory references
├── pbm_database.db          # Standalone SQLite database file
├── run.py                   # Flask server launcher script (http://127.0.0.1:5000)
├── seed_db.py               # Database initialization and seeding CLI utility
├── requirements.txt         # Dependencies (Flask, PyMySQL, Cryptography)
└── README.md                # Project documentation
```

---

## MySQL / MariaDB Setup Guide

### Method A: Direct Command Prompt / Terminal Import (Recommended)

1. Open your **MySQL** or **MariaDB command prompt** (or Windows Command Prompt / PowerShell / Bash):
   ```bash
   mysql -u root -p < database.sql
   ```
   *(Or in MariaDB cmd)*:
   ```bash
   mariadb -u root -p < database.sql
   ```

2. If you are already inside the MySQL/MariaDB interactive shell:
   ```sql
   SOURCE /path/to/Case-Study/database.sql;
   ```

This script automatically creates the database **`` `Case-Study` ``**, builds the tables (`breaches`, `case_studies`, `sources`), and populates all 80+ authentic breach records and case studies.

---

### Method B: Seed via Python CLI

You can also seed directly into MySQL / MariaDB using the Python utility:

```bash
# Seed default MySQL localhost
python seed_db.py --mysql

# Or with custom credentials / host / port:
python seed_db.py --mysql --host localhost --port 3306 --user root --password your_password --db Case-Study --reset
```

---

## Running the Web Application

### 1. Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Database Environment (Optional)
If your MySQL / MariaDB runs on custom ports or passwords, set the environment variables:

**Linux / macOS / Git Bash**:
```bash
export MYSQL_HOST=localhost
export MYSQL_PORT=3306
export MYSQL_USER=root
export MYSQL_PASSWORD=your_password
export MYSQL_DB=Case-Study
```

**Windows CMD**:
```cmd
set MYSQL_HOST=localhost
set MYSQL_PORT=3306
set MYSQL_USER=root
set MYSQL_PASSWORD=your_password
set MYSQL_DB=Case-Study
```

**Windows PowerShell**:
```powershell
$env:MYSQL_HOST="localhost"
$env:MYSQL_PORT="3306"
$env:MYSQL_USER="root"
$env:MYSQL_PASSWORD="your_password"
$env:MYSQL_DB="Case-Study"
```

### 3. Start the Web Server
```bash
python run.py
```

Access the Web Application at:
👉 **`http://127.0.0.1:5000`**

---

## Database Schema (Database: `Case-Study`)

### 1. Table: `breaches`
- `id` (VARCHAR(64) PRIMARY KEY) — e.g. `PBM-EQFX`, `PBM-CPO1`
- `breach_name` (VARCHAR(255))
- `organization` (VARCHAR(255))
- `industry` (VARCHAR(100))
- `breach_date` (VARCHAR(30))
- `discovery_date` (VARCHAR(30))
- `affected_records` (BIGINT)
- `severity` (VARCHAR(50))
- `breach_type` (VARCHAR(100))
- `attack_vector` (VARCHAR(100))
- `data_exposed` (TEXT)
- `root_cause` (TEXT)
- `status` (VARCHAR(50))

### 2. Table: `case_studies`
- `id` (INT AUTO_INCREMENT PRIMARY KEY)
- `breach_id` (VARCHAR(64) FOREIGN KEY -> `breaches.id`)
- `title` (VARCHAR(255))
- `subtitle` (VARCHAR(255))
- `date` (VARCHAR(30))
- `severity` (VARCHAR(50))
- `executive_summary` (TEXT)
- `timeline_json` (MEDIUMTEXT)
- `response` (TEXT)
- `attack_vector_tags` (TEXT)
- `root_cause` (TEXT)
- `data_exposed_tags` (TEXT)
- `impact_metrics` (TEXT)
- `lessons_learned` (TEXT)

### 3. Table: `sources`
- `id` (INT AUTO_INCREMENT PRIMARY KEY)
- `breach_id` (VARCHAR(64))
- `source_type` (VARCHAR(100))
- `title` (VARCHAR(255))
- `authority_or_publisher` (VARCHAR(255))
- `url` (TEXT)
- `publication_year` (VARCHAR(30))
- `citation_note` (TEXT)

---

## Running Automated Tests

Run the test suite to verify database integrity, API routes, report generation, and MySQL compatibility:

```bash
python -m unittest tests/test_api.py
```
*(All 14 unit test specs execute with 100% pass rate).*
