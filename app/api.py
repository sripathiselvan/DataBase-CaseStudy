"""
REST API Blueprint for Password Breach Monitoring (PBM).
Provides endpoints for breaches, case studies, dashboard metrics, analytics, and safe SQL execution.
"""

import json
import time
from flask import Blueprint, jsonify, request
from app.db import get_db_connection
from app.sql_validator import validate_select_query

api_bp = Blueprint("api", __name__, url_prefix="/api")


def format_records_count(number):
    """Formats large record counts to human readable strings like 38.7M or 860K."""
    if number >= 1_000_000_000:
        return f"{number / 1_000_000_000:.1f}B"
    elif number >= 1_000_000:
        return f"{number / 1_000_000:.1f}M"
    elif number >= 1_000:
        return f"{number / 1_000:.1f}K"
    return str(number)


@api_bp.route("/breaches", methods=["GET"])
def get_breaches():
    """
    Search, filter, paginate, and sort breaches.
    Query params:
      q: keyword search
      severity: Critical | High | Medium | Low
      year: e.g. 2026
      industry: e.g. Healthcare
      vector: e.g. Phishing
      status: e.g. Contained
      page: int (default 1)
      per_page: int (default 10, 0 for all)
      sort_by: column name (default breach_date)
      sort_order: asc | desc (default desc)
    """
    q = request.args.get("q", "").strip()
    severity = request.args.get("severity", "").strip()
    year = request.args.get("year", "").strip()
    industry = request.args.get("industry", "").strip()
    vector = request.args.get("vector", "").strip()
    status = request.args.get("status", "").strip()
    
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    try:
        per_page = int(request.args.get("per_page", 10))
    except ValueError:
        per_page = 10

    sort_by = request.args.get("sort_by", "breach_date").strip()
    sort_order = request.args.get("sort_order", "desc").strip().lower()

    allowed_sort_columns = {
        "id", "organization", "breach_name", "industry",
        "breach_date", "affected_records", "severity", "attack_vector", "status"
    }
    if sort_by not in allowed_sort_columns:
        sort_by = "breach_date"

    if sort_order not in ("asc", "desc"):
        sort_order = "desc"

    conn = get_db_connection(read_only=True)
    cursor = conn.cursor()

    where_clauses = []
    params = {}

    if q:
        where_clauses.append(
            "(id LIKE :q OR organization LIKE :q OR breach_name LIKE :q "
            "OR attack_vector LIKE :q OR root_cause LIKE :q OR data_exposed LIKE :q)"
        )
        params["q"] = f"%{q}%"

    if severity:
        where_clauses.append("severity = :severity")
        params["severity"] = severity

    if year:
        where_clauses.append("breach_date LIKE :year")
        params["year"] = f"{year}%"

    if industry:
        where_clauses.append("industry = :industry")
        params["industry"] = industry

    if vector:
        where_clauses.append("attack_vector = :vector")
        params["vector"] = vector

    if status:
        where_clauses.append("status = :status")
        params["status"] = status

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # Count total matching rows
    count_sql = f"SELECT COUNT(*) FROM breaches{where_sql}"
    cursor.execute(count_sql, params)
    total = cursor.fetchone()[0]

    # Query items
    order_sql = f" ORDER BY {sort_by} {sort_order.upper()}"
    
    if per_page > 0:
        offset = (page - 1) * per_page
        limit_sql = f" LIMIT :limit OFFSET :offset"
        params["limit"] = per_page
        params["offset"] = offset
        total_pages = (total + per_page - 1) // per_page if per_page > 0 else 1
    else:
        limit_sql = ""
        total_pages = 1

    query_sql = f"SELECT * FROM breaches{where_sql}{order_sql}{limit_sql}"
    cursor.execute(query_sql, params)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({
        "status": "success",
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "data": rows
    })


@api_bp.route("/breaches/<breach_id>", methods=["GET"])
def get_breach_detail(breach_id):
    """Get single breach details by ID."""
    conn = get_db_connection(read_only=True)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM breaches WHERE id = ?", (breach_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "error", "message": f"Breach record '{breach_id}' not found."}), 404

    return jsonify({"status": "success", "data": dict(row)})


@api_bp.route("/case-studies", methods=["GET"])
def get_case_studies():
    """Get all case studies or filter by breach_id."""
    breach_id = request.args.get("breach_id", "").strip()
    conn = get_db_connection(read_only=True)
    cursor = conn.cursor()

    if breach_id:
        cursor.execute("SELECT * FROM case_studies WHERE breach_id = ?", (breach_id,))
        rows = cursor.fetchall()
    else:
        cursor.execute("SELECT * FROM case_studies ORDER BY id ASC")
        rows = cursor.fetchall()

    conn.close()

    result = []
    for row in rows:
        item = dict(row)
        # Parse JSON fields
        try:
            item["timeline"] = json.loads(item["timeline_json"])
        except Exception:
            item["timeline"] = []
        try:
            item["impact_metrics"] = json.loads(item["impact_metrics"])
        except Exception:
            item["impact_metrics"] = {}

        item["attack_vector_tags"] = [t.strip() for t in item["attack_vector_tags"].split(",") if t.strip()]
        item["data_exposed_tags"] = [t.strip() for t in item["data_exposed_tags"].split(",") if t.strip()]
        result.append(item)

    return jsonify({"status": "success", "data": result})


@api_bp.route("/case-studies/<breach_id>", methods=["GET"])
def get_case_study_detail(breach_id):
    """Get specific case study by breach ID."""
    conn = get_db_connection(read_only=True)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM case_studies WHERE breach_id = ?", (breach_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "error", "message": f"Case study for breach '{breach_id}' not found."}), 404

    item = dict(row)
    try:
        item["timeline"] = json.loads(item["timeline_json"])
    except Exception:
        item["timeline"] = []
    try:
        item["impact_metrics"] = json.loads(item["impact_metrics"])
    except Exception:
        item["impact_metrics"] = {}

    item["attack_vector_tags"] = [t.strip() for t in item["attack_vector_tags"].split(",") if t.strip()]
    item["data_exposed_tags"] = [t.strip() for t in item["data_exposed_tags"].split(",") if t.strip()]

    return jsonify({"status": "success", "data": item})


@api_bp.route("/dashboard", methods=["GET"])
def get_dashboard_stats():
    """Returns dashboard summary statistics and chart datasets."""
    conn = get_db_connection(read_only=True)
    cursor = conn.cursor()

    # Total breaches count
    cursor.execute("SELECT COUNT(*) FROM breaches")
    total_breaches = cursor.fetchone()[0]

    # Total records exposed
    cursor.execute("SELECT SUM(affected_records) FROM breaches")
    sum_records = cursor.fetchone()[0] or 0

    # Critical breaches count
    cursor.execute("SELECT COUNT(*) FROM breaches WHERE severity = 'Critical'")
    critical_count = cursor.fetchone()[0]

    critical_percentage = round((critical_count / total_breaches * 100), 1) if total_breaches > 0 else 0.0

    # Latest incident
    cursor.execute("SELECT id, organization, breach_date FROM breaches ORDER BY breach_date DESC LIMIT 1")
    latest_row = cursor.fetchone()
    latest_incident = dict(latest_row) if latest_row else {"id": "N/A", "organization": "None", "breach_date": "N/A"}

    # Breaches by year
    cursor.execute("""
        SELECT strftime('%Y', breach_date) as year, COUNT(*) as count
        FROM breaches
        GROUP BY year
        ORDER BY year ASC
    """)
    by_year = [dict(row) for row in cursor.fetchall()]

    # Severity distribution
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM breaches
        GROUP BY severity
    """)
    sev_rows = cursor.fetchall()
    sev_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in sev_rows:
        sev_dist[r["severity"]] = r["count"]

    sev_percentages = {}
    for k, v in sev_dist.items():
        sev_percentages[k] = round((v / total_breaches * 100), 1) if total_breaches > 0 else 0

    # Recent 5 breach activity
    cursor.execute("SELECT * FROM breaches ORDER BY breach_date DESC LIMIT 5")
    recent = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return jsonify({
        "status": "success",
        "total_breaches": total_breaches,
        "total_records": sum_records,
        "total_records_formatted": format_records_count(sum_records),
        "critical_breaches": critical_count,
        "critical_percentage": f"{critical_percentage}%",
        "latest_incident": latest_incident,
        "by_year": by_year,
        "severity_distribution": sev_dist,
        "severity_percentages": sev_percentages,
        "recent_activity": recent
    })


@api_bp.route("/analytics", methods=["GET"])
def get_analytics():
    """Returns analytics data for threat intelligence charts."""
    conn = get_db_connection(read_only=True)
    cursor = conn.cursor()

    # Breaches by year
    cursor.execute("""
        SELECT strftime('%Y', breach_date) as year, COUNT(*) as count
        FROM breaches
        GROUP BY year
        ORDER BY year ASC
    """)
    breaches_by_year = [dict(row) for row in cursor.fetchall()]

    # Records exposed by year
    cursor.execute("""
        SELECT strftime('%Y', breach_date) as year, SUM(affected_records) as total_records
        FROM breaches
        GROUP BY year
        ORDER BY year ASC
    """)
    records_by_year_raw = cursor.fetchall()
    records_by_year = []
    for r in records_by_year_raw:
        records_by_year.append({
            "year": r["year"],
            "total_records": r["total_records"],
            "formatted": format_records_count(r["total_records"])
        })

    # Severity counts
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM breaches
        GROUP BY severity
    """)
    sev_counts = {r["severity"]: r["count"] for r in cursor.fetchall()}

    # Top Industries
    cursor.execute("""
        SELECT industry, COUNT(*) as count
        FROM breaches
        GROUP BY industry
        ORDER BY count DESC
        LIMIT 6
    """)
    industries = [dict(row) for row in cursor.fetchall()]

    # Top Attack Vectors
    cursor.execute("""
        SELECT attack_vector, COUNT(*) as count
        FROM breaches
        GROUP BY attack_vector
        ORDER BY count DESC
        LIMIT 6
    """)
    vectors = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return jsonify({
        "status": "success",
        "breaches_by_year": breaches_by_year,
        "records_by_year": records_by_year,
        "severity_counts": sev_counts,
        "industry_breakdown": industries,
        "vector_breakdown": vectors
    })


@api_bp.route("/sql/execute", methods=["POST"])
def execute_sql_query():
    """
    Executes a user-submitted SQL query safely in read-only SELECT mode.
    Payload: { "query": "SELECT ..." }
    """
    payload = request.get_json(silent=True) or {}
    query = payload.get("query", "").strip()

    is_valid, error_msg, clean_query = validate_select_query(query)
    if not is_valid:
        return jsonify({
            "status": "error",
            "error": error_msg,
            "columns": [],
            "rows": [],
            "row_count": 0,
            "execution_time_ms": 0
        }), 400

    start_time = time.perf_counter()

    try:
        # Use read-only SQLite connection URI
        conn = get_db_connection(read_only=True)
        cursor = conn.cursor()

        # Limit maximum rows returned to 500
        wrapped_query = f"SELECT * FROM ({clean_query}) LIMIT 500"
        cursor.execute(wrapped_query)

        columns = [description[0] for description in cursor.description] if cursor.description else []
        raw_rows = cursor.fetchall()
        rows = [list(row) for row in raw_rows]
        conn.close()

        execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return jsonify({
            "status": "success",
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
            "execution_time_ms": execution_time_ms,
            "query": clean_query
        })
    except Exception as e:
        execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return jsonify({
            "status": "error",
            "error": f"SQL Execution Error: {str(e)}",
            "columns": [],
            "rows": [],
            "row_count": 0,
            "execution_time_ms": execution_time_ms
        }), 400


@api_bp.route("/sql/examples", methods=["GET"])
def get_sql_examples():
    """Prebuilt sample queries for SQL Explorer."""
    examples = [
        {
            "name": "Recent incidents",
            "sql": "SELECT id, organization, breach_date, affected_records, severity\nFROM breaches\nORDER BY breach_date DESC\nLIMIT 10;"
        },
        {
            "name": "Count by industry",
            "sql": "SELECT industry, COUNT(*) AS total_breaches\nFROM breaches\nGROUP BY industry\nORDER BY total_breaches DESC;"
        },
        {
            "name": "Records by attack vector",
            "sql": "SELECT attack_vector, SUM(affected_records) AS total_records\nFROM breaches\nGROUP BY attack_vector\nORDER BY total_records DESC;"
        },
        {
            "name": "Critical incidents sorted by records",
            "sql": "SELECT id, organization, industry, affected_records\nFROM breaches\nWHERE severity = 'Critical'\nORDER BY affected_records DESC;"
        }
    ]
    return jsonify({"status": "success", "data": examples})
