"""
Database module for Password Breach Monitoring (PBM).
Handles SQLite schema creation, connection management, queries, and data seeding.
Keeps all breach intelligence, case studies, and citations in a single SQLite database file (pbm_database.db).
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
    Creates database tables if they do not exist and seeds authentic historical data.
    """
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

    # Create sources table in the single database file
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

    # Check if breaches table is empty or if reseed is requested
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

        # Seed primary verified regulatory & threat intelligence sources
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
        print(f"Successfully initialized and seeded database with {len(breaches)} authentic breach records and {len(CASE_STUDIES)} case studies.")

    conn.close()
