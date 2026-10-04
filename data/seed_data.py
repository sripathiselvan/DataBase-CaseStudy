"""
Seed data generator for Password Breach Monitoring (PBM) Database.
Generates 120 realistic fictional breach records and detailed case studies.
"""

import random
from datetime import datetime, timedelta

# Existing anchor breaches matching frontend mock dataset
ANCHOR_BREACHES = [
    {
        "id": "PBM-0284",
        "breach_name": "Northstar Legacy Transit Portal Leak",
        "organization": "Northstar Transit",
        "industry": "Transport",
        "breach_date": "2026-09-28",
        "discovery_date": "2026-09-29",
        "affected_records": 2100000,
        "severity": "Critical",
        "breach_type": "Credential Leak",
        "attack_vector": "Credential stuffing",
        "data_exposed": "Email aliases, Salted hashes, Transit IDs, Timestamps",
        "root_cause": "Automated reuse of exposed credentials against retired customer endpoint.",
        "status": "Contained"
    },
    {
        "id": "PBM-0283",
        "breach_name": "Lumen Grove Retail Staff Credential Harvest",
        "organization": "Lumen Grove Retail",
        "industry": "Retail",
        "breach_date": "2026-09-17",
        "discovery_date": "2026-09-18",
        "affected_records": 860000,
        "severity": "High",
        "breach_type": "Phishing Capture",
        "attack_vector": "Phishing",
        "data_exposed": "Customer account exports, Email addresses, Order metadata",
        "root_cause": "Spear phishing campaign compromised staff credentials with access to internal portal.",
        "status": "Investigating"
    },
    {
        "id": "PBM-0279",
        "breach_name": "Meridian Ledger Storage Bucket Exposure",
        "organization": "Meridian Ledger",
        "industry": "Finance",
        "breach_date": "2026-08-06",
        "discovery_date": "2026-08-08",
        "affected_records": 340000,
        "severity": "Medium",
        "breach_type": "Database Exposure",
        "attack_vector": "Cloud misconfiguration",
        "data_exposed": "Transaction logs, Account IDs, Hashed security tokens",
        "root_cause": "Storage access policy was incorrectly set to public during cloud migration.",
        "status": "Resolved"
    },
    {
        "id": "PBM-0272",
        "breach_name": "Cedarline Student Identity Hijack",
        "organization": "Cedarline University",
        "industry": "Education",
        "breach_date": "2026-06-21",
        "discovery_date": "2026-06-22",
        "affected_records": 1200000,
        "severity": "High",
        "breach_type": "Session Hijack",
        "attack_vector": "Stolen session",
        "data_exposed": "Student portal logins, bcrypt password hashes, Directory info",
        "root_cause": "Compromised admin session token permitted unauthenticated directory export.",
        "status": "Contained"
    },
    {
        "id": "PBM-0261",
        "breach_name": "Aster Peak Healthcare Endpoint Compromise",
        "organization": "Aster Peak Health",
        "industry": "Healthcare",
        "breach_date": "2026-02-14",
        "discovery_date": "2026-02-14",
        "affected_records": 4800000,
        "severity": "Critical",
        "breach_type": "API Exfiltration",
        "attack_vector": "Legacy endpoint",
        "data_exposed": "Email aliases, Password hashes, Account IDs, Timestamps",
        "root_cause": "Rate-limit drift and incomplete MFA enforcement on a legacy authentication endpoint.",
        "status": "Resolved"
    },
    {
        "id": "PBM-0248",
        "breach_name": "Orbit Harbor Support Tool Leak",
        "organization": "Orbit Harbor Systems",
        "industry": "Technology",
        "breach_date": "2025-11-03",
        "discovery_date": "2025-11-05",
        "affected_records": 620000,
        "severity": "Medium",
        "breach_type": "Supply Chain Breach",
        "attack_vector": "Supply chain",
        "data_exposed": "Account profile data, Support ticket transcripts, API keys",
        "root_cause": "Third-party vendor analytics tool compromised via unpatched vulnerability.",
        "status": "Resolved"
    },
    {
        "id": "PBM-0231",
        "breach_name": "Willow Arc Executive Phishing Breach",
        "organization": "Willow Arc Finance",
        "industry": "Finance",
        "breach_date": "2025-07-19",
        "discovery_date": "2025-07-20",
        "affected_records": 3100000,
        "severity": "Critical",
        "breach_type": "MFA Bypass",
        "attack_vector": "Phishing",
        "data_exposed": "Admin credentials, Financial account numbers, PBKDF2 password hashes",
        "root_cause": "Targeted social engineering captured administrative credentials and session cookies.",
        "status": "Contained"
    },
    {
        "id": "PBM-0197",
        "breach_name": "Helix Orchard Test Directory Leak",
        "organization": "Helix Orchard Labs",
        "industry": "Technology",
        "breach_date": "2024-10-08",
        "discovery_date": "2024-10-09",
        "affected_records": 95000,
        "severity": "Low",
        "breach_type": "Database Exposure",
        "attack_vector": "Access policy error",
        "data_exposed": "Test account credentials, Synthetic identity records",
        "root_cause": "Internal access control misconfiguration exposed non-production test directory.",
        "status": "Resolved"
    }
]

ORGANIZATIONS = [
    ("Aegis Cloud Security", "Technology"),
    ("Vanguard Logistics", "Transport"),
    ("Apex BioTech", "Healthcare"),
    ("Zenith Health Systems", "Healthcare"),
    ("Aura Communications", "Telecommunications"),
    ("Pinnacle Capital", "Finance"),
    ("Titan Mobility", "Transport"),
    ("Quantum Microprocessors", "Technology"),
    ("Nova Energy Corp", "Energy"),
    ("Aether Digital", "Technology"),
    ("Hyperion Media", "Media"),
    ("Sovereign Trust Bank", "Finance"),
    ("Crestview Insurance", "Finance"),
    ("Veritas Defense", "Government"),
    ("Solaris Energy", "Energy"),
    ("Omni Retail Group", "Retail"),
    ("BioGenetics Global", "Healthcare"),
    ("Starlight Airlines", "Transport"),
    ("NextGen Telecommunications", "Telecommunications"),
    ("Beacon Mutual Funds", "Finance"),
    ("Summit University Systems", "Education"),
    ("Chronos Software", "Technology"),
    ("Atlas Rail Network", "Transport"),
    ("Pulse Health Alliance", "Healthcare"),
    ("Echo Media Networks", "Media"),
    ("Prism Cybernetics", "Technology"),
    ("Cascade Water Services", "Energy"),
    ("Valence Financial", "Finance"),
    ("Horizon Logistics", "Transport"),
    ("Frontier Academic Portal", "Education"),
    ("Spectra Mobile", "Telecommunications"),
    ("Krypton Networks", "Technology"),
    ("Solstice Cloud", "Technology"),
    ("Beacon Health Care", "Healthcare"),
    ("Orion E-Commerce", "Retail"),
    ("Nimbus Gaming", "Media"),
    ("Terraform Infrastructure", "Energy"),
    ("Ironclad Security", "Government"),
    ("Silverline Bank", "Finance"),
    ("Velocity Express", "Transport")
]

ATTACK_VECTORS = [
    "Credential stuffing",
    "Phishing",
    "Cloud misconfiguration",
    "Supply chain",
    "Stolen session",
    "Legacy endpoint",
    "Access policy error",
    "Zero-day exploit",
    "API Key leak"
]

BREACH_TYPES = [
    "Credential Leak",
    "Database Exposure",
    "Session Hijack",
    "API Exfiltration",
    "Source Code Leak",
    "MFA Bypass",
    "Insider Threat"
]

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEVERITY_WEIGHTS = [0.35, 0.30, 0.22, 0.13]

STATUSES = ["Contained", "Resolved", "Investigating"]

DATA_EXPOSED_OPTIONS = [
    "Email aliases, Salted SHA-256 hashes, User IDs",
    "Email addresses, bcrypt password hashes, Account profile details",
    "Phone numbers, Plaintext session tokens, Account metadata",
    "Username list, Argon2id password hashes, Security question responses",
    "OAuth tokens, Email addresses, API access keys",
    "Billing history, Hashed passwords, Customer names",
    "Employee IDs, Internal email logs, Salted password hashes",
    "SSN last-4 digits, Salted MD5 hashes, Address records",
    "User profile metadata, Password reset tokens, Device fingerprints",
    "Customer IDs, Transaction logs, Hashed credentials"
]

ROOT_CAUSES = [
    "Outdated authentication service exposed via unpatched vulnerability.",
    "Database backup left in public S3 bucket without access restrictions.",
    "Staff developer pushed production credentials to public code repository.",
    "Credential stuffing attack automated using residential proxy network.",
    "Employee fell victim to SMS phishing campaign bypassing single-factor auth.",
    "Deprecation of legacy portal was delayed, leaving unmonitored endpoint active.",
    "Malicious software infection on administrative workstation harvested credentials.",
    "Third-party vendor API key compromised during vendor breach.",
    "Missing rate limits on password reset endpoint permitted brute force enumeration.",
    "Wildcard CORS header and permissive session handling enabled cross-site token theft.",
    "Privilege escalation vulnerability in self-hosted identity server.",
    "Hardcoded API access key discovered in decompiled client mobile application."
]


def generate_breach_records(total_count=120):
    records = list(ANCHOR_BREACHES)
    used_ids = {b["id"] for b in records}

    # Deterministic seed for reproducible testing data
    random.seed(20261004)

    # Years distribution (2020 to 2026)
    start_date = datetime(2020, 1, 15)
    end_date = datetime(2026, 9, 28)
    time_span_days = (end_date - start_date).days

    id_counter = 1
    while len(records) < total_count:
        id_str = f"PBM-{id_counter:04d}"
        id_counter += 1
        if id_str in used_ids:
            continue

        org, industry = random.choice(ORGANIZATIONS)
        b_type = random.choice(BREACH_TYPES)
        vector = random.choice(ATTACK_VECTORS)
        severity = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS)[0]
        status = random.choice(STATUSES)

        days_offset = random.randint(0, time_span_days)
        b_date_dt = start_date + timedelta(days=days_offset)
        disc_offset = random.randint(1, 14)
        disc_date_dt = b_date_dt + timedelta(days=disc_offset)

        b_date = b_date_dt.strftime("%Y-%m-%d")
        disc_date = disc_date_dt.strftime("%Y-%m-%d")

        if severity == "Critical":
            records_count = random.randint(2000000, 15000000)
        elif severity == "High":
            records_count = random.randint(800000, 3500000)
        elif severity == "Medium":
            records_count = random.randint(150000, 950000)
        else:
            records_count = random.randint(15000, 200000)

        data_exp = random.choice(DATA_EXPOSED_OPTIONS)
        root_cause = random.choice(ROOT_CAUSES)
        breach_name = f"{org} {b_type} ({b_date_dt.year})"

        records.append({
            "id": id_str,
            "breach_name": breach_name,
            "organization": org,
            "industry": industry,
            "breach_date": b_date,
            "discovery_date": disc_date,
            "affected_records": records_count,
            "severity": severity,
            "breach_type": b_type,
            "attack_vector": vector,
            "data_exposed": data_exp,
            "root_cause": root_cause,
            "status": status
        })

    # Sort descending by breach date
    records.sort(key=lambda x: x["breach_date"], reverse=True)
    return records


CASE_STUDIES = [
    {
        "breach_id": "PBM-0261",
        "title": "Aster Peak Health Incident",
        "subtitle": "Sanitized educational analysis · 14 February 2026",
        "date": "2026-02-14",
        "severity": "Critical",
        "executive_summary": "A fictional healthcare services provider identified unauthorized access to a legacy identity service. The simulated incident affected 4.8 million records containing account metadata and password hashes. No plaintext credentials or real personal data are included in this study.",
        "timeline_json": '[{"time": "2026-02-11 · 02:18 UTC", "title": "Anomalous authentication detected", "description": "Monitoring identified a burst of successful logins from unfamiliar infrastructure."}, {"time": "2026-02-11 · 03:02 UTC", "title": "Identity service isolated", "description": "The response team revoked active sessions and segmented the affected service."}, {"time": "2026-02-12 · 15:40 UTC", "title": "Scope confirmed", "description": "Review established exposure of account metadata and salted password hashes."}, {"time": "2026-02-14 · 09:00 UTC", "title": "Notification initiated", "description": "Affected simulated users were enrolled in a mandatory credential reset."}]',
        "response": "All sessions were invalidated, access keys rotated, legacy authentication endpoints retired, and identity telemetry centralized. A simulated notification process and independent review followed.",
        "attack_vector_tags": "Credential stuffing, Legacy endpoint, Session abuse",
        "root_cause": "Rate-limit policy drift on a deprecated authentication endpoint, compounded by incomplete MFA enforcement.",
        "data_exposed_tags": "Email aliases, Password hashes, Account IDs, Timestamps",
        "impact_metrics": '{"records": "4.8M", "exposure_window": "31h", "sessions_reset": "100%", "plaintext_passwords": "0"}',
        "lessons_learned": "Retire legacy endpoints decisively, enforce MFA consistently, test rate limits continuously, and maintain centralized identity-service observability."
    },
    {
        "breach_id": "PBM-0284",
        "title": "Northstar Transit Legacy Portal Exposure",
        "subtitle": "Automated credential spray case study · 28 September 2026",
        "date": "2026-09-28",
        "severity": "Critical",
        "executive_summary": "A major regional transport authority detected automated login attacks targeting a legacy web portal. Approximately 2.1 million records containing user transit account metadata and password hashes were exposed.",
        "timeline_json": '[{"time": "2026-09-28 · 01:10 UTC", "title": "High volume login spike", "description": "Automated alert triggered by 50,000 requests per minute to /v1/auth endpoint."}, {"time": "2026-09-28 · 02:30 UTC", "title": "IP Range Blocked", "description": "WAF rules applied to block bad bot traffic."}, {"time": "2026-09-29 · 10:00 UTC", "title": "Portal Offline", "description": "Legacy portal permanently taken offline and user passwords reset."}]',
        "response": "The deprecated customer portal was completely decommissioned, force-resets were pushed to all users, and automated bot prevention controls were deployed across all active gateways.",
        "attack_vector_tags": "Credential stuffing, Legacy portal, Bot traffic",
        "root_cause": "Unmonitored legacy API endpoint lacked modern bot detection and IP throttling.",
        "data_exposed_tags": "Email aliases, Transit IDs, Password hashes",
        "impact_metrics": '{"records": "2.1M", "exposure_window": "12h", "sessions_reset": "100%", "plaintext_passwords": "0"}',
        "lessons_learned": "Perform regular audits to ensure sunset services are fully taken offline and removed from DNS records."
    }
]
