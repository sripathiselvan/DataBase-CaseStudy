"""
Automated Test Suite for Password Breach Monitoring (PBM) REST API & SQLite Database.
Validates authentic real-world data, single database storage integrity,
executive summarized report generation, data sources catalog, and safe SQL security.
"""

import json
import unittest
from app import create_app
from app.db import get_db_connection, DB_PATH


class PbmApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def test_01_database_records_count(self):
        """Verify single SQLite database contains 80+ real breach records and 12 case studies."""
        self.assertTrue(DB_PATH.exists(), "Database file pbm_database.db must exist.")
        conn = get_db_connection(read_only=True)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM breaches")
        breach_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM case_studies")
        cs_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM sources")
        sources_count = cursor.fetchone()[0]

        conn.close()
        self.assertGreaterEqual(breach_count, 80, f"Expected at least 80 real breach records, found {breach_count}")
        self.assertGreaterEqual(cs_count, 12, f"Expected at least 12 real case studies, found {cs_count}")
        self.assertGreaterEqual(sources_count, 15, f"Expected verified sources in database, found {sources_count}")
        print(f"\n[PASS] Single SQLite Database (pbm_database.db) verified: {breach_count} real breaches, {cs_count} case studies, {sources_count} source citations.")

    def test_02_get_breaches_api(self):
        """Test GET /api/breaches with search and filtering."""
        res = self.client.get("/api/breaches?page=1&per_page=10")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(len(data["data"]), 10)
        self.assertGreaterEqual(data["total"], 80)

        # Test filtering by severity
        res_crit = self.client.get("/api/breaches?severity=Critical")
        data_crit = res_crit.get_json()
        for item in data_crit["data"]:
            self.assertEqual(item["severity"], "Critical")

        # Test search query for real breach
        res_search = self.client.get("/api/breaches?q=Equifax")
        data_search = res_search.get_json()
        self.assertGreater(data_search["total"], 0)
        self.assertEqual(data_search["data"][0]["organization"], "Equifax")
        print("[PASS] GET /api/breaches returns real records with fast filtering & search.")

    def test_03_get_breach_detail(self):
        """Test GET /api/breaches/<id>."""
        res = self.client.get("/api/breaches/PBM-EQFX")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["data"]["organization"], "Equifax")
        self.assertTrue(data["data"]["has_case_study"])

        # Test non-existent ID
        res_404 = self.client.get("/api/breaches/PBM-NONEXISTENT")
        self.assertEqual(res_404.status_code, 404)
        print("[PASS] GET /api/breaches/<id> returned real breach details & sources.")

    def test_04_get_case_studies(self):
        """Test GET /api/case-studies."""
        res = self.client.get("/api/case-studies/PBM-EQFX")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("timeline", data["data"])
        self.assertIn("impact_metrics", data["data"])
        self.assertIn("lessons_learned", data["data"])
        print("[PASS] GET /api/case-studies returned complete structured forensics analysis.")

    def test_05_generate_case_study_report(self):
        """Test GET /api/reports/case-study/<id> generates comprehensive summarized report."""
        res = self.client.get("/api/reports/case-study/PBM-EQFX")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        rep = data["data"]
        self.assertIn("report_id", rep)
        self.assertIn("executive_summary", rep)
        self.assertIn("exposure_scorecard", rep)
        self.assertIn("nist_csf_mapping", rep)
        self.assertIn("sources_and_citations", rep)
        print(f"[PASS] Executive Summarized Report generated for {rep['title']}.")

    def test_06_generate_summary_landscape_report(self):
        """Test GET /api/reports/summary generates consolidated threat briefing."""
        res = self.client.get("/api/reports/summary")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("strategic_recommendations", data["data"])
        self.assertGreater(len(data["data"]["case_studies_summaries"]), 10)
        print("[PASS] Consolidated Executive Threat Landscape Briefing generated.")

    def test_07_export_breaches_csv(self):
        """Test GET /api/breaches/export generates downloadable CSV format."""
        res = self.client.get("/api/breaches/export")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "text/csv")
        self.assertIn("Equifax", res.data.decode("utf-8"))
        print("[PASS] CSV export generated with authentic breach rows.")

    def test_08_sources_catalog(self):
        """Test GET /api/sources returns verified regulatory sources."""
        res = self.client.get("/api/sources")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertGreater(len(data["sources"]), 10)
        self.assertIn("FTC", data["raw_documentation"])
        print("[PASS] Verified Data Sources & Citations catalog retrieved.")

    def test_09_dashboard_stats(self):
        """Test GET /api/dashboard."""
        res = self.client.get("/api/dashboard")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertGreaterEqual(data["total_breaches"], 80)
        self.assertIn("total_records_formatted", data)
        self.assertIn("by_year", data)
        print("[PASS] GET /api/dashboard returned summary metrics & line chart dataset.")

    def test_10_analytics(self):
        """Test GET /api/analytics."""
        res = self.client.get("/api/analytics")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("breaches_by_year", data)
        self.assertIn("industry_breakdown", data)
        self.assertIn("vector_breakdown", data)
        print("[PASS] GET /api/analytics returned aggregated threat metrics.")

    def test_11_sql_explorer_safe_select(self):
        """Test POST /api/sql/execute with valid SELECT query."""
        payload = {"query": "SELECT id, organization, affected_records FROM breaches WHERE severity = 'Critical' LIMIT 5"}
        res = self.client.post("/api/sql/execute", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["columns"], ["id", "organization", "affected_records"])
        self.assertEqual(len(data["rows"]), 5)
        self.assertIn("execution_time_ms", data)
        print(f"[PASS] Safe SELECT query executed on SQLite in {data['execution_time_ms']} ms.")

    def test_12_sql_explorer_blocked_mutations(self):
        """Test POST /api/sql/execute blocks INSERT, UPDATE, DELETE, DROP, ALTER, PRAGMA."""
        blocked_queries = [
            "DELETE FROM breaches",
            "DROP TABLE breaches",
            "UPDATE breaches SET severity = 'Low'",
            "INSERT INTO breaches (id, breach_name) VALUES ('X', 'Y')",
            "ALTER TABLE breaches ADD COLUMN secret TEXT",
            "CREATE TABLE hack (id INT)",
            "TRUNCATE breaches",
            "PRAGMA table_info(breaches)",
            "SELECT * FROM breaches; DROP TABLE breaches;"
        ]

        for query in blocked_queries:
            res = self.client.post("/api/sql/execute", json={"query": query})
            self.assertEqual(res.status_code, 400, f"Query should have been blocked: {query}")
            data = res.get_json()
            self.assertEqual(data["status"], "error")
            self.assertIn("error", data)

        print(f"[PASS] All {len(blocked_queries)} disallowed mutation/administrative queries were properly blocked.")

    def test_13_database_info_endpoint(self):
        """Test GET /api/db/info returns engine and connection configuration."""
        res = self.client.get("/api/db/info")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("engine", data["data"])
        self.assertIn("mysql_database", data["data"])
        self.assertEqual(data["data"]["mysql_database"], "Case-Study")
        print(f"[PASS] Database info endpoint verified (Active engine: {data['data']['engine']}, Target MySQL DB: {data['data']['mysql_database']}).")

    def test_14_mysql_wrapper_query_translation(self):
        """Test MySQLCursorWrapper parameter conversion logic."""
        from app.db import MySQLCursorWrapper
        wrapper = MySQLCursorWrapper(None)
        
        # Test named parameter conversion :name -> %(name)s
        q1, p1 = wrapper._convert_query_and_params(
            "SELECT * FROM breaches WHERE severity = :severity AND industry = :industry",
            {"severity": "Critical", "industry": "Finance"}
        )
        self.assertEqual(q1, "SELECT * FROM breaches WHERE severity = %(severity)s AND industry = %(industry)s")
        self.assertEqual(p1, {"severity": "Critical", "industry": "Finance"})

        # Test positional parameter conversion ? -> %s
        q2, p2 = wrapper._convert_query_and_params(
            "SELECT * FROM breaches WHERE id = ?",
            ("PBM-EQFX",)
        )
        self.assertEqual(q2, "SELECT * FROM breaches WHERE id = %s")
        self.assertEqual(p2, ("PBM-EQFX",))
        print("[PASS] MySQLCursorWrapper parameter conversion (:name -> %(name)s, ? -> %s) validated.")


if __name__ == "__main__":
    unittest.main()
