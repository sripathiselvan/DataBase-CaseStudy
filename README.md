# Password Breach Monitoring (PBM) Database — Backend & SQLite Platform

A full-stack cybersecurity threat intelligence and case-study platform built with **Python**, **Flask**, and **SQLite**. The system provides 100% real and authentic breach intelligence data, a consolidated executive summary report covering all data, threat analytics, and a sandboxed read-only SQL Explorer.

---

## Key Features & Highlights

1. **Clean Modern White Theme**:
   - High-contrast, clean light-themed UI designed for clarity, readability, and professional reporting.
   - Pure white executive document presentation for case studies and reports (print- and PDF-ready).

2. **100% Real & Authentic Breach Intelligence**:
   - Zero synthetic/fake data.
   - Sourced from official regulatory enforcement orders (US FTC, SEC, DOJ), CISA advisories, Mandiant threat reports, and published post-mortems.
   - Comprehensive documentation in [`DATA_SOURCES.txt`](file:///home/eclipse/Projects/Case-Study/DATA_SOURCES.txt).

3. **Consolidated Executive Summarized Report (All Data)**:
   - Directly compiles a comprehensive executive briefing summarizing all 80+ documented incidents and case studies across the database.
   - Includes: *Macro Threat Synopsis, Exposure Scorecard, Targeted Industry Risk Ranking, Attack Vector Taxonomy, Chronological Threat Eras, Landmark Case Studies Forensic Summary, NIST Cybersecurity Framework (CSF 2.0) Matrix, Strategic CISO Directives, and Regulatory Citations*.
   - Instant export options: **Print / Save as PDF**, **Download Markdown (.md)**, **Download Plain Text (.txt)**, **Export JSON**, and **Copy to Clipboard**.

4. **Single-File SQLite Architecture**:
   - All relational entities (`breaches`, `case_studies`, `sources`) are strictly stored in a single SQLite database file: `pbm_database.db`.

5. **Interactive Read-Only SQL Explorer**:
   - Sandboxed query builder with instant visual toggles and safe execution enforcement (`mode=ro`).

---

## Directory Structure

```
Case-Study/
├── app/
│   ├── __init__.py          # Flask Application Factory & Route Registration
│   ├── api.py               # REST API Blueprint (Breaches, Case Studies, Reports, Analytics, SQL Runner)
│   ├── db.py                # Single-file SQLite Database Interface & Schema Manager
│   └── sql_validator.py     # Safe Read-Only SELECT Query Security Validator
├── data/
│   └── seed_data.py         # 80+ real-world historical breach records & 12 in-depth case studies
├── static/
│   ├── css/
│   │   └── style.css        # Clean White / Light Theme CSS design system
│   └── js/
│       └── app.js           # Frontend client with report generator & async API integration
├── templates/
│   └── index.html           # Modern semantic HTML5 dashboard template
├── tests/
│   └── test_api.py          # Automated PyUnit test suite validating 12 test specs
├── DATA_SOURCES.txt         # Comprehensive verified citations and regulatory references
├── pbm_database.db          # Single SQLite database file
├── run.py                   # Flask server launcher script (http://127.0.0.1:5000)
├── seed_db.py               # Database initialization and seeding CLI utility
├── requirements.txt         # Dependencies (Flask)
└── README.md                # Project documentation
```

---

## Getting Started

### 1. Requirements

- Python 3.8+
- `pip`

### 2. Setup Virtual Environment & Dependencies

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Initialize / Seed Database

To seed or reset the database with the authentic dataset:

```bash
python seed_db.py --reset
```

### 4. Run Application

```bash
python run.py
```

Access the Web Application in your browser at:
**`http://127.0.0.1:5000`**

---

## Database Schema (`pbm_database.db`)

### Table: `breaches`
- `id` (TEXT PRIMARY KEY) — E.g., `PBM-EQFX`, `PBM-CPO1`
- `breach_name` (TEXT)
- `organization` (TEXT)
- `industry` (TEXT)
- `breach_date` (TEXT)
- `discovery_date` (TEXT)
- `affected_records` (INTEGER)
- `severity` (TEXT)
- `breach_type` (TEXT)
- `attack_vector` (TEXT)
- `data_exposed` (TEXT)
- `root_cause` (TEXT)
- `status` (TEXT)

### Table: `case_studies`
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
- `breach_id` (TEXT FOREIGN KEY)
- `title` (TEXT)
- `subtitle` (TEXT)
- `date` (TEXT)
- `severity` (TEXT)
- `executive_summary` (TEXT)
- `timeline_json` (TEXT)
- `response` (TEXT)
- `attack_vector_tags` (TEXT)
- `root_cause` (TEXT)
- `data_exposed_tags` (TEXT)
- `impact_metrics` (TEXT)
- `lessons_learned` (TEXT)

### Table: `sources`
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
- `breach_id` (TEXT)
- `source_type` (TEXT)
- `title` (TEXT)
- `authority_or_publisher` (TEXT)
- `url` (TEXT)
- `publication_year` (TEXT)
- `citation_note` (TEXT)

---

## Running Automated Tests

Run the test suite using `unittest`:

```bash
python -m unittest tests/test_api.py
```
