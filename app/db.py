"""
Database module for Password Breach Monitoring (PBM).
Supports both MySQL / MariaDB and SQLite database backends with automatic detection,
graceful fallback, and unified dictionary-like query execution.

Target Database: `Case-Study` (MySQL / MariaDB) or `pbm_database.db` (SQLite single-file).
"""

import os
import re
import sqlite3
from pathlib import Path

# Pure-Python MySQL/MariaDB driver
try:
    import pymysql
    import pymysql.cursors
    PYMYSQL_AVAILABLE = True
except ImportError:
    PYMYSQL_AVAILABLE = False

DB_PATH = Path(__file__).resolve().parent.parent / "pbm_database.db"

# MySQL / MariaDB Configuration from environment variables
MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", 3306))
MYSQL_USER = os.environ.get("MYSQL_USER", "root")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
MYSQL_DB = os.environ.get("MYSQL_DB", "Case-Study")
FORCE_DB_ENGINE = os.environ.get("DB_ENGINE", "").strip().lower()  # "mysql" or "sqlite"


def is_mysql_configured_and_alive():
    """Checks if MySQL / MariaDB is available and reachable."""
    if not PYMYSQL_AVAILABLE:
        return False
    if FORCE_DB_ENGINE == "sqlite":
        return False
    try:
        conn = pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            connect_timeout=2
        )
        conn.close()
        return True
    except Exception:
        return False


def get_active_engine():
    """Returns 'mysql' if MySQL/MariaDB is configured or requested and available, else 'sqlite'."""
    if FORCE_DB_ENGINE == "mysql":
        return "mysql"
    if FORCE_DB_ENGINE == "sqlite":
        return "sqlite"
    if is_mysql_configured_and_alive():
        return "mysql"
    return "sqlite"


class MySQLCursorWrapper:
    """
    Wraps PyMySQL DictCursor to provide seamless parameter conversion (:param -> %(param)s and ? -> %s)
    and uniform dictionary-like row access.
    """
    def __init__(self, cursor):
        self._cursor = cursor

    def _convert_query_and_params(self, query, params):
        if params is None:
            return query, None

        if isinstance(params, dict):
            # Convert :named_param into %(named_param)s
            converted_query = re.sub(r':([a-zA-Z_][a-zA-Z0-9_]*)', r'%(\1)s', query)
            return converted_query, params

        if isinstance(params, (list, tuple)):
            # Convert ? into %s
            converted_query = query.replace("?", "%s")
            return converted_query, params

        return query, params

    def execute(self, query, params=None):
        clean_q, clean_p = self._convert_query_and_params(query, params)
        if clean_p is not None:
            return self._cursor.execute(clean_q, clean_p)
        return self._cursor.execute(clean_q)

    def executemany(self, query, seq_of_params):
        if not seq_of_params:
            return 0
        first_item = seq_of_params[0]
        if isinstance(first_item, dict):
            clean_q = re.sub(r':([a-zA-Z_][a-zA-Z0-9_]*)', r'%(\1)s', query)
        elif isinstance(first_item, (list, tuple)):
            clean_q = query.replace("?", "%s")
        else:
            clean_q = query
        return self._cursor.executemany(clean_q, seq_of_params)

    def fetchone(self):
        row = self._cursor.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self):
        rows = self._cursor.fetchall()
        return [dict(r) for r in rows]

    @property
    def description(self):
        return self._cursor.description

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def close(self):
        self._cursor.close()


class MySQLConnectionWrapper:
    """Wraps PyMySQL Connection to match sqlite3 connection API."""
    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        return MySQLCursorWrapper(self._conn.cursor(pymysql.cursors.DictCursor))

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def get_db_connection(read_only=False, force_engine=None):
    """
    Returns a unified Connection object.
    Automatically connects to MySQL / MariaDB (database `Case-Study`) when available,
    or falls back to SQLite (`pbm_database.db`).
    """
    engine = force_engine or get_active_engine()

    if engine == "mysql" and PYMYSQL_AVAILABLE:
        try:
            # First ensure database `Case-Study` exists or connect directly
            raw_conn = pymysql.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DB,
                charset="utf8mb4",
                autocommit=True,
                cursorclass=pymysql.cursors.DictCursor
            )
            return MySQLConnectionWrapper(raw_conn)
        except Exception:
            # If `Case-Study` database does not exist yet, connect to root and create it
            try:
                raw_conn = pymysql.connect(
                    host=MYSQL_HOST,
                    port=MYSQL_PORT,
                    user=MYSQL_USER,
                    password=MYSQL_PASSWORD,
                    charset="utf8mb4",
                    autocommit=True
                )
                with raw_conn.cursor() as cur:
                    cur.execute(f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DB}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
                    cur.execute(f"USE `{MYSQL_DB}`")
                raw_conn.select_db(MYSQL_DB)
                return MySQLConnectionWrapper(raw_conn)
            except Exception as e:
                # If MySQL is unreachable, fallback gracefully to SQLite
                print(f"[PBM DB] Note: Could not connect to MySQL ({e}). Falling back to SQLite database ({DB_PATH.name}).")

    # SQLite fallback / default
    if read_only and DB_PATH.exists():
        uri = f"file:{DB_PATH.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def get_db_info():
    """Returns metadata about the active database engine and connection."""
    active_engine = get_active_engine()
    return {
        "engine": active_engine,
        "is_mysql": active_engine == "mysql",
        "mysql_host": MYSQL_HOST,
        "mysql_port": MYSQL_PORT,
        "mysql_user": MYSQL_USER,
        "mysql_database": MYSQL_DB,
        "sqlite_path": str(DB_PATH)
    }


def init_db(force_reseed=False, target_engine=None):
    """
    Creates database tables if they do not exist and seeds authentic historical data.
    Works for both MySQL / MariaDB (`Case-Study`) and SQLite (`pbm_database.db`).
    """
    engine = target_engine or get_active_engine()

    if engine == "mysql" and PYMYSQL_AVAILABLE:
        try:
            # Connect to MySQL server and ensure `Case-Study` database exists
            root_conn = pymysql.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                charset="utf8mb4",
                autocommit=True
            )
            with root_conn.cursor() as cur:
                cur.execute(f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DB}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
            root_conn.close()

            conn = get_db_connection(read_only=False, force_engine="mysql")
            cursor = conn.cursor()

            # Create breaches table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `breaches` (
                    `id` VARCHAR(64) NOT NULL,
                    `breach_name` VARCHAR(255) NOT NULL,
                    `organization` VARCHAR(255) NOT NULL,
                    `industry` VARCHAR(100) NOT NULL,
                    `breach_date` VARCHAR(30) NOT NULL,
                    `discovery_date` VARCHAR(30) NOT NULL,
                    `affected_records` BIGINT NOT NULL,
                    `severity` VARCHAR(50) NOT NULL,
                    `breach_type` VARCHAR(100) NOT NULL,
                    `attack_vector` VARCHAR(100) NOT NULL,
                    `data_exposed` TEXT NOT NULL,
                    `root_cause` TEXT NOT NULL,
                    `status` VARCHAR(50) NOT NULL,
                    PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """)

            # Create case_studies table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `case_studies` (
                    `id` INT NOT NULL AUTO_INCREMENT,
                    `breach_id` VARCHAR(64) NOT NULL,
                    `title` VARCHAR(255) NOT NULL,
                    `subtitle` VARCHAR(255) NOT NULL,
                    `date` VARCHAR(30) NOT NULL,
                    `severity` VARCHAR(50) NOT NULL,
                    `executive_summary` TEXT NOT NULL,
                    `timeline_json` MEDIUMTEXT NOT NULL,
                    `response` TEXT NOT NULL,
                    `attack_vector_tags` TEXT NOT NULL,
                    `root_cause` TEXT NOT NULL,
                    `data_exposed_tags` TEXT NOT NULL,
                    `impact_metrics` TEXT NOT NULL,
                    `lessons_learned` TEXT NOT NULL,
                    PRIMARY KEY (`id`),
                    FOREIGN KEY (`breach_id`) REFERENCES `breaches` (`id`) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """)

            # Create sources table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `sources` (
                    `id` INT NOT NULL AUTO_INCREMENT,
                    `breach_id` VARCHAR(64) NOT NULL,
                    `source_type` VARCHAR(100) NOT NULL,
                    `title` VARCHAR(255) NOT NULL,
                    `authority_or_publisher` VARCHAR(255) NOT NULL,
                    `url` TEXT NOT NULL,
                    `publication_year` VARCHAR(30) NOT NULL,
                    `citation_note` TEXT,
                    PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """)

            # Check if breaches table is empty or if reseed is requested
            cursor.execute("SELECT COUNT(*) as c FROM `breaches`")
            row = cursor.fetchone()
            count = row["c"] if row else 0

            if count == 0 or force_reseed:
                from data.seed_data import generate_breach_records, CASE_STUDIES

                if force_reseed:
                    cursor.execute("DELETE FROM `sources`")
                    cursor.execute("DELETE FROM `case_studies`")
                    cursor.execute("DELETE FROM `breaches`")

                breaches = generate_breach_records()
                cursor.executemany("""
                    INSERT INTO `breaches` (
                        `id`, `breach_name`, `organization`, `industry`, `breach_date`,
                        `discovery_date`, `affected_records`, `severity`, `breach_type`,
                        `attack_vector`, `data_exposed`, `root_cause`, `status`
                    ) VALUES (
                        :id, :breach_name, :organization, :industry, :breach_date,
                        :discovery_date, :affected_records, :severity, :breach_type,
                        :attack_vector, :data_exposed, :root_cause, :status
                    )
                """, breaches)

                for cs in CASE_STUDIES:
                    cursor.execute("""
                        INSERT INTO `case_studies` (
                            `breach_id`, `title`, `subtitle`, `date`, `severity`,
                            `executive_summary`, `timeline_json`, `response`,
                            `attack_vector_tags`, `root_cause`, `data_exposed_tags`,
                            `impact_metrics`, `lessons_learned`
                        ) VALUES (
                            :breach_id, :title, :subtitle, :date, :severity,
                            :executive_summary, :timeline_json, :response,
                            :attack_vector_tags, :root_cause, :data_exposed_tags,
                            :impact_metrics, :lessons_learned
                        )
                    """, cs)

                official_sources = [
                    {"breach_id": "PBM-EQFX", "source_type": "Regulatory Settlement", "title": "FTC Settlement with Equifax Over 2017 Data Breach", "authority_or_publisher": "Federal Trade Commission (FTC)", "url": "https://www.ftc.gov/news-events/news/press-releases/2019/07/ftc-cfpb-and-states-announce-settlement-equifax-over-2017-data-breach", "publication_year": "2019", "citation_note": "FTC File No. 172 3203 · $575M Settlement"},
                    {"breach_id": "PBM-EQFX", "source_type": "DOJ Indictment", "title": "US Indictment of PLA Hackers for 2017 Equifax Breach", "authority_or_publisher": "US Department of Justice", "url": "https://www.justice.gov/opa/pr/chinese-military-personnel-charged-computer-fraud-economic-espionage-and-wire-fraud-hacking", "publication_year": "2020", "citation_note": "Case 1:20-cr-00030"},
                    {"breach_id": "PBM-CPO1", "source_type": "DOJ Conviction", "title": "Former Tech Worker Convicted in Capital One Cloud Intrusion", "authority_or_publisher": "US Department of Justice (W.D. Wash.)", "url": "https://www.justice.gov/usao-wdwa/pr/former-seattle-tech-worker-convicted-wire-fraud-and-computer-intrusions", "publication_year": "2022", "citation_note": "W.D. Wash. Conviction"},
                    {"breach_id": "PBM-CPO1", "source_type": "Regulatory Order", "title": "OCC Civil Money Penalty Order against Capital One ($80M)", "authority_or_publisher": "Office of the Comptroller of the Currency (OCC)", "url": "https://www.occ.gov/news-issuances/news-releases/2020/nr-occ-2020-101.html", "publication_year": "2020", "citation_note": "AA-EC-2020-48"},
                    {"breach_id": "PBM-YAHO", "source_type": "SEC Enforcement", "title": "Altaba (f/k/a Yahoo!) $35M Penalty for Cyber Breach Failure to Disclose", "authority_or_publisher": "Securities and Exchange Commission (SEC)", "url": "https://www.sec.gov/news/press-release/2018-71", "publication_year": "2018", "citation_note": "Release No. 2018-71"},
                    {"breach_id": "PBM-YAHO", "source_type": "DOJ Indictment", "title": "US Charges Russian FSB Officers in Yahoo! Hack", "authority_or_publisher": "US Department of Justice", "url": "https://www.justice.gov/opa/pr/us-charges-russian-fsb-officers-and-their-conspirators-hacking-yahoo-and-millions-email-accounts", "publication_year": "2017", "citation_note": "Indictment No. 17-CR-00103"},
                    {"breach_id": "PBM-LPAS", "source_type": "Vendor Advisory", "title": "LastPass Security Incident Update & Recommended Actions", "authority_or_publisher": "LastPass Security Advisory", "url": "https://blog.lastpass.com/posts/2023/03/security-incident-update-recommended-actions", "publication_year": "2023", "citation_note": "Official Technical Post-Mortem"},
                    {"breach_id": "PBM-23ME", "source_type": "SEC Filing", "title": "23andMe Holding Co. Form 8-K Disclosure", "authority_or_publisher": "Securities and Exchange Commission (SEC)", "url": "https://www.sec.gov/edgar/browse/?CIK=0001804591", "publication_year": "2023", "citation_note": "Form 8-K Dec 2023"},
                    {"breach_id": "PBM-MRRT", "source_type": "GDPR Enforcement", "title": "ICO Fines Marriott International £18.4M for GDPR Violations", "authority_or_publisher": "UK Information Commissioner's Office (ICO)", "url": "https://ico.org.uk/about-the-ico/news-and-events/news-and-blogs/2020/10/ico-fines-marriott-international-inc-184m-for-gdpr-breaches/", "publication_year": "2020", "citation_note": "Penalty Notice COM0804337"},
                    {"breach_id": "PBM-TRGT", "source_type": "Congressional Report", "title": "A Kill Chain Analysis of the 2013 Target Data Breach", "authority_or_publisher": "US Senate Committee on Commerce, Science & Transportation", "url": "https://www.commerce.senate.gov", "publication_year": "2014", "citation_note": "Majority Staff Report"},
                    {"breach_id": "PBM-UBER", "source_type": "DOJ Conviction", "title": "Former Chief Security Officer Of Uber Convicted Of Concealing Breach", "authority_or_publisher": "US Department of Justice (N.D. Cal.)", "url": "https://www.justice.gov/usao-ndca/pr/former-chief-security-officer-uber-convicted-federal-charges-covering-data-breach", "publication_year": "2022", "citation_note": "Case 3:20-cr-00375-WHO"},
                    {"breach_id": "PBM-SLRW", "source_type": "CISA Advisory", "title": "Alert AA20-352A: Advanced Persistent Threat Compromise of Infrastructure", "authority_or_publisher": "Cybersecurity & Infrastructure Security Agency (CISA)", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a", "publication_year": "2020", "citation_note": "Emergency Directive 21-01"},
                    {"breach_id": "PBM-CHNG", "source_type": "HHS Civil Rights", "title": "HHS OCR Initiates Investigation into Change Healthcare Cybersecurity Incident", "authority_or_publisher": "US Dept of Health and Human Services (HHS)", "url": "https://www.hhs.gov/about/news/2024/03/13/hhs-office-civil-rights-initiates-investigation-change-healthcare-cybersecurity-incident.html", "publication_year": "2024", "citation_note": "HHS OCR Notice"},
                    {"breach_id": "PBM-SNOW", "source_type": "Threat Intelligence", "title": "UNC5537 Targeting Snowflake Customer Database Environments", "authority_or_publisher": "Mandiant / Google Cloud Security", "url": "https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion", "publication_year": "2024", "citation_note": "Mandiant Report M-Trends"},
                    {"breach_id": "PBM-CNVA", "source_type": "Security Advisory", "title": "Canva Customer Security Incident Notification", "authority_or_publisher": "Canva Security Advisory / Have I Been Pwned", "url": "https://haveibeenpwned.com/PwnedWebsites#Canva", "publication_year": "2019", "citation_note": "HIBP Incident Directory"},
                    {"breach_id": "ALL", "source_type": "Breach Index", "title": "Have I Been Pwned Pwned Websites Directory", "authority_or_publisher": "Have I Been Pwned (Troy Hunt)", "url": "https://haveibeenpwned.com/PwnedWebsites", "publication_year": "2026", "citation_note": "Curated Index of Verified Breaches"},
                    {"breach_id": "ALL", "source_type": "Threat Report", "title": "Verizon Data Breach Investigations Report (DBIR)", "authority_or_publisher": "Verizon Threat Research", "url": "https://www.verizon.com/business/resources/reports/dbir/", "publication_year": "2024", "citation_note": "Annual Empirical Threat Metric Analysis"}
                ]

                cursor.executemany("""
                    INSERT INTO `sources` (
                        `breach_id`, `source_type`, `title`, `authority_or_publisher`, `url`, `publication_year`, `citation_note`
                    ) VALUES (
                        :breach_id, :source_type, :title, :authority_or_publisher, :url, :publication_year, :citation_note
                    )
                """, official_sources)

                conn.commit()
                print(f"[PBM MySQL] Successfully initialized and seeded MySQL/MariaDB database `{MYSQL_DB}` with {len(breaches)} authentic breach records and {len(CASE_STUDIES)} case studies.")

            conn.close()
            return
        except Exception as e:
            print(f"[PBM DB] MySQL initialization failed ({e}). Initializing SQLite fallback...")

    # SQLite initialization
    conn = get_db_connection(read_only=False, force_engine="sqlite")
    cursor = conn.cursor()

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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            breach_id TEXT NOT NULL,
            source_type TEXT NOT NULL,
            title TEXT NOT NULL,
            authority_or_publisher TEXT NOT NULL,
            url TEXT NOT NULL,
            publication_year TEXT NOT NULL,
            citation_note TEXT,
            FOREIGN KEY (breach_id) REFERENCES breaches (id)
        )
    """)

    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM breaches")
    count = cursor.fetchone()[0]

    if count == 0 or force_reseed:
        from data.seed_data import generate_breach_records, CASE_STUDIES

        if force_reseed:
            cursor.execute("DELETE FROM sources")
            cursor.execute("DELETE FROM case_studies")
            cursor.execute("DELETE FROM breaches")

        breaches = generate_breach_records()
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

        official_sources = [
            ("PBM-EQFX", "Regulatory Settlement", "FTC Settlement with Equifax Over 2017 Data Breach", "Federal Trade Commission (FTC)", "https://www.ftc.gov/news-events/news/press-releases/2019/07/ftc-cfpb-and-states-announce-settlement-equifax-over-2017-data-breach", "2019", "FTC File No. 172 3203 · $575M Settlement"),
            ("PBM-EQFX", "DOJ Indictment", "US Indictment of PLA Hackers for 2017 Equifax Breach", "US Department of Justice", "https://www.justice.gov/opa/pr/chinese-military-personnel-charged-computer-fraud-economic-espionage-and-wire-fraud-hacking", "2020", "Case 1:20-cr-00030"),
            ("PBM-CPO1", "DOJ Conviction", "Former Tech Worker Convicted in Capital One Cloud Intrusion", "US Department of Justice (W.D. Wash.)", "https://www.justice.gov/usao-wdwa/pr/former-seattle-tech-worker-convicted-wire-fraud-and-computer-intrusions", "2022", "W.D. Wash. Conviction"),
            ("PBM-CPO1", "Regulatory Order", "OCC Civil Money Penalty Order against Capital One ($80M)", "Office of the Comptroller of the Currency (OCC)", "https://www.occ.gov/news-issuances/news-releases/2020/nr-occ-2020-101.html", "2020", "AA-EC-2020-48"),
            ("PBM-YAHO", "SEC Enforcement", "Altaba (f/k/a Yahoo!) $35M Penalty for Cyber Breach Failure to Disclose", "Securities and Exchange Commission (SEC)", "https://www.sec.gov/news/press-release/2018-71", "2018", "Release No. 2018-71"),
            ("PBM-YAHO", "DOJ Indictment", "US Charges Russian FSB Officers in Yahoo! Hack", "US Department of Justice", "https://www.justice.gov/opa/pr/us-charges-russian-fsb-officers-and-their-conspirators-hacking-yahoo-and-millions-email-accounts", "2017", "Indictment No. 17-CR-00103"),
            ("PBM-LPAS", "Vendor Advisory", "LastPass Security Incident Update & Recommended Actions", "LastPass Security Advisory", "https://blog.lastpass.com/posts/2023/03/security-incident-update-recommended-actions", "2023", "Official Technical Post-Mortem"),
            ("PBM-23ME", "SEC Filing", "23andMe Holding Co. Form 8-K Disclosure", "Securities and Exchange Commission (SEC)", "https://www.sec.gov/edgar/browse/?CIK=0001804591", "2023", "Form 8-K Dec 2023"),
            ("PBM-MRRT", "GDPR Enforcement", "ICO Fines Marriott International £18.4M for GDPR Violations", "UK Information Commissioner's Office (ICO)", "https://ico.org.uk/about-the-ico/news-and-events/news-and-blogs/2020/10/ico-fines-marriott-international-inc-184m-for-gdpr-breaches/", "2020", "Penalty Notice COM0804337"),
            ("PBM-TRGT", "Congressional Report", "A Kill Chain Analysis of the 2013 Target Data Breach", "US Senate Committee on Commerce, Science & Transportation", "https://www.commerce.senate.gov", "2014", "Majority Staff Report"),
            ("PBM-UBER", "DOJ Conviction", "Former Chief Security Officer Of Uber Convicted Of Concealing Breach", "US Department of Justice (N.D. Cal.)", "https://www.justice.gov/usao-ndca/pr/former-chief-security-officer-uber-convicted-federal-charges-covering-data-breach", "2022", "Case 3:20-cr-00375-WHO"),
            ("PBM-SLRW", "CISA Advisory", "Alert AA20-352A: Advanced Persistent Threat Compromise of Infrastructure", "Cybersecurity & Infrastructure Security Agency (CISA)", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a", "2020", "Emergency Directive 21-01"),
            ("PBM-CHNG", "HHS Civil Rights", "HHS OCR Initiates Investigation into Change Healthcare Cybersecurity Incident", "US Dept of Health and Human Services (HHS)", "https://www.hhs.gov/about/news/2024/03/13/hhs-office-civil-rights-initiates-investigation-change-healthcare-cybersecurity-incident.html", "2024", "HHS OCR Notice"),
            ("PBM-SNOW", "Threat Intelligence", "UNC5537 Targeting Snowflake Customer Database Environments", "Mandiant / Google Cloud Security", "https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion", "2024", "Mandiant Report M-Trends"),
            ("PBM-CNVA", "Security Advisory", "Canva Customer Security Incident Notification", "Canva Security Advisory / Have I Been Pwned", "https://haveibeenpwned.com/PwnedWebsites#Canva", "2019", "HIBP Incident Directory"),
            ("ALL", "Breach Index", "Have I Been Pwned Pwned Websites Directory", "Have I Been Pwned (Troy Hunt)", "https://haveibeenpwned.com/PwnedWebsites", "2026", "Curated Index of Verified Breaches"),
            ("ALL", "Threat Report", "Verizon Data Breach Investigations Report (DBIR)", "Verizon Threat Research", "https://www.verizon.com/business/resources/reports/dbir/", "2024", "Annual Empirical Threat Metric Analysis")
        ]

        cursor.executemany("""
            INSERT INTO sources (
                breach_id, source_type, title, authority_or_publisher, url, publication_year, citation_note
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, official_sources)

        conn.commit()
        print(f"[PBM SQLite] Successfully initialized and seeded database with {len(breaches)} authentic breach records and {len(CASE_STUDIES)} case studies.")

    conn.close()
