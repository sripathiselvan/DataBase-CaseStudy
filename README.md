# Password Breach Monitoring (PBM) Database — Backend & SQLite Platform

A full-stack cybersecurity case-study platform built with **Python**, **Flask**, and **SQLite**. The system provides REST API endpoints, real-time threat intelligence analytics, search/filtering, detailed case study views, and a sandboxed read-only SQL Explorer.

---

## Architecture & Technology Stack

- **Backend**: Python 3.14 + Flask (Modular Application Factory & REST API Blueprints)
- **Database**: SQLite 3 (`pbm_database.db`)
- **Frontend**: HTML5, Vanilla CSS3 (Custom Glassmorphism Design System), JavaScript (ES6+ async/await API integration)
- **Security Engine**: Custom SQL Query Security Validator permitting read-only `SELECT` statements and executing via read-only SQLite URI handles (`mode=ro`).

---

## Directory Structure

```
Case-Study/
├── app/
│   ├── __init__.py          # Flask Application Factory & Route Registration
│   ├── api.py               # REST API Blueprint (Breaches, Case Studies, Dashboard, Analytics, SQL Runner)
│   ├── db.py                # SQLite Database Interface & Schema Manager
│   └── sql_validator.py     # Safe Read-Only SELECT Query Security Validator
├── data/
│   └── seed_data.py         # Data generator for 120+ realistic fictional breach records & case studies
├── static/
│   ├── css/
│   │   └── style.css        # Glassmorphism dark-theme CSS stylesheet
│   └── js/
│       └── app.js           # Frontend client interacting asynchronously with Flask REST API
├── templates/
│   └── index.html           # Refactored semantic HTML dashboard template
├── tests/
│   └── test_api.py          # Automated PyUnit test suite validating schema, REST APIs & SQL security
├── pbm_database.db          # SQLite database file (automatically initialized)
├── run.py                   # Flask server launcher script (http://127.0.0.1:5000)
├── seed_db.py               # Standalone CLI database seeding utility
├── requirements.txt         # Dependencies (Flask)
└── README.md                # Documentation & API Specification
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

The SQLite database is initialized automatically when starting the application. To manually reset or re-seed 120+ fictional breach records, run:

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

## Database Schema

### Table: `breaches`

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | TEXT PRIMARY KEY | Unique ID (e.g., `PBM-0261`) |
| `breach_name` | TEXT | Descriptive breach title |
| `organization` | TEXT | Organization name |
| `industry` | TEXT | Healthcare, Finance, Transport, Retail, Technology, Education, etc. |
| `breach_date` | TEXT | ISO Date (`YYYY-MM-DD`) |
| `discovery_date` | TEXT | ISO Date (`YYYY-MM-DD`) |
| `affected_records` | INTEGER | Total count of records exposed |
| `severity` | TEXT | `Critical`, `High`, `Medium`, `Low` |
| `breach_type` | TEXT | `Credential Leak`, `Database Exposure`, `Session Hijack`, `API Exfiltration`, etc. |
| `attack_vector` | TEXT | `Credential stuffing`, `Phishing`, `Cloud misconfiguration`, `Supply chain`, etc. |
| `data_exposed` | TEXT | Summary of exposed attributes (e.g. Email aliases, Password hashes) |
| `root_cause` | TEXT | Root cause explanation |
| `status` | TEXT | `Contained`, `Resolved`, `Investigating` |

### Table: `case_studies`

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER PRIMARY KEY | Primary key |
| `breach_id` | TEXT | Foreign key referencing `breaches(id)` |
| `title` | TEXT | Case study title |
| `subtitle` | TEXT | Date & analysis classification |
| `executive_summary` | TEXT | High-level incident summary |
| `timeline_json` | TEXT | JSON string array of incident events |
| `response` | TEXT | Containment & remediation details |
| `attack_vector_tags` | TEXT | Comma-separated attack vectors |
| `root_cause` | TEXT | Technical root cause |
| `data_exposed_tags` | TEXT | Comma-separated exposed data types |
| `impact_metrics` | TEXT | JSON string of metrics (`records`, `exposure_window`, etc.) |
| `lessons_learned` | TEXT | Key prevention takeaways |

---

## REST API Documentation

### 1. `GET /api/breaches`
Search, filter, paginate, and sort breach records.

- **Query Parameters**:
  - `q`: Search keyword matching organization, vector, root cause, or ID
  - `severity`: `Critical` \| `High` \| `Medium` \| `Low`
  - `year`: Year string (e.g. `2026`)
  - `industry`: Industry name
  - `page`: Page number (default: `1`)
  - `per_page`: Page size (default: `10`)
  - `sort_by`: Field name (`breach_date`, `affected_records`, `organization`, `severity`, `id`)
  - `sort_order`: `desc` \| `asc`

### 2. `GET /api/breaches/<id>`
Fetch detail for a single breach record by ID (e.g. `/api/breaches/PBM-0261`).

### 3. `GET /api/case-studies/<breach_id>`
Fetch structured incident case study analysis.

### 4. `GET /api/dashboard`
Fetch high-level operational statistics, SVG line chart coordinates for yearly breaches, severity donut distribution, and 5 recent breach events.

### 5. `GET /api/analytics`
Fetch aggregated threat intelligence breakdown by year, records exposed, severity distribution, top industries, and top attack vectors.

### 6. `POST /api/sql/execute`
Safe SQL execution endpoint for the SQL Explorer tool.

- **Request Body**:
  ```json
  {
    "query": "SELECT organization, affected_records, severity FROM breaches WHERE severity = 'Critical' ORDER BY affected_records DESC LIMIT 10;"
  }
  ```
- **Security Controls**:
  - Only `SELECT` statements are permitted.
  - Blocks `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`, `REPLACE`, `TRUNCATE`, `PRAGMA`, `ATTACH`, `DETACH`, multi-statement semicolons, and SQL comments.
  - Connects using SQLite `mode=ro` (read-only mode).

---

## Running Automated Tests

Run the test suite using `unittest`:

```bash
python -m unittest tests/test_api.py
```
