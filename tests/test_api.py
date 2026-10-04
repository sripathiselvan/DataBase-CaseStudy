"""
Automated Test Suite for Password Breach Monitoring (PBM) REST API & Database.
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
        """Verify SQLite database contains 100+ fictional breach records."""
        self.assertTrue(DB_PATH.exists(), "Database file pbm_database.db must exist.")
        conn = get_db_connection(read_only=True)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM breaches")
        count = cursor.fetchone()[0]
        conn.close()
        self.assertGreaterEqual(count, 100, f"Expected at least 100 breach records, found {count}")
        print(f"\n[PASS] SQLite Database contains {count} breach records.")

    def test_02_get_breaches_api(self):
        """Test GET /api/breaches with search and filtering."""
        res = self.client.get("/api/breaches?page=1&per_page=10")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(len(data["data"]), 10)
        self.assertGreaterEqual(data["total"], 100)

        # Test filtering by severity
        res_crit = self.client.get("/api/breaches?severity=Critical")
        data_crit = res_crit.get_json()
        for item in data_crit["data"]:
            self.assertEqual(item["severity"], "Critical")

        # Test search query
        res_search = self.client.get("/api/breaches?q=Northstar")
        data_search = res_search.get_json()
        self.assertGreater(data_search["total"], 0)
        print("[PASS] GET /api/breaches returned expected data & search filters work.")

    def test_03_get_breach_detail(self):
        """Test GET /api/breaches/<id>."""
        res = self.client.get("/api/breaches/PBM-0261")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["data"]["organization"], "Aster Peak Health")

        # Test non-existent ID
        res_404 = self.client.get("/api/breaches/PBM-999999")
        self.assertEqual(res_404.status_code, 404)
        print("[PASS] GET /api/breaches/<id> returned detail view.")

    def test_04_get_case_studies(self):
        """Test GET /api/case-studies."""
        res = self.client.get("/api/case-studies/PBM-0261")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("timeline", data["data"])
        self.assertIn("impact_metrics", data["data"])
        print("[PASS] GET /api/case-studies returned case study analysis.")

    def test_05_dashboard_stats(self):
        """Test GET /api/dashboard."""
        res = self.client.get("/api/dashboard")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertGreaterEqual(data["total_breaches"], 100)
        self.assertIn("total_records_formatted", data)
        self.assertIn("by_year", data)
        self.assertIn("severity_distribution", data)
        print("[PASS] GET /api/dashboard returned summary metrics & line chart dataset.")

    def test_06_analytics(self):
        """Test GET /api/analytics."""
        res = self.client.get("/api/analytics")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("breaches_by_year", data)
        self.assertIn("industry_breakdown", data)
        self.assertIn("vector_breakdown", data)
        print("[PASS] GET /api/analytics returned aggregated threat metrics.")

    def test_07_sql_explorer_safe_select(self):
        """Test POST /api/sql/execute with valid SELECT query."""
        payload = {"query": "SELECT id, organization, affected_records FROM breaches WHERE severity = 'Critical' LIMIT 5"}
        res = self.client.post("/api/sql/execute", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["columns"], ["id", "organization", "affected_records"])
        self.assertEqual(len(data["rows"]), 5)
        self.assertIn("execution_time_ms", data)
        print(f"[PASS] Safe SELECT query executed in {data['execution_time_ms']} ms.")

    def test_08_sql_explorer_blocked_mutations(self):
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


if __name__ == "__main__":
    unittest.main()
