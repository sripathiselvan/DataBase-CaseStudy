"""
Safe SQL Query Security Validator for Password Breach Monitoring (PBM).
Ensures only read-only SELECT statements are allowed for execution in the SQL Explorer.
Blocks any mutation (INSERT, UPDATE, DELETE, DROP, ALTER, etc.), DDL, DCL, multi-statements,
comment obfuscation tricks, or dangerous pragmas.
"""

import re

# Blacklisted SQL keywords that mutate database state or alter runtime parameters
DISALLOWED_KEYWORDS = {
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "REPLACE",
    "TRUNCATE", "PRAGMA", "ATTACH", "DETACH", "VACUUM", "REINDEX",
    "GRANT", "REVOKE", "SAVEPOINT", "RELEASE", "BEGIN", "COMMIT",
    "ROLLBACK", "EXEC", "EXECUTE", "LOAD_EXTENSION", "EXPLAIN"
}

def remove_sql_comments(sql: str) -> str:
    """Removes single-line (-- ...) and multi-line (/* ... */) SQL comments."""
    # Remove block comments
    sql = re.sub(r'/\*.*?\*/', ' ', sql, flags=re.DOTALL)
    # Remove line comments
    sql = re.sub(r'--.*$', '', sql, flags=re.MULTILINE)
    return sql.strip()

def check_multiple_statements(sql: str) -> bool:
    """
    Returns True if the SQL contains multiple statements separated by semicolons
    outside of string literals.
    """
    in_single_quote = False
    in_double_quote = False
    escaped = False

    semicolon_count = 0
    for char in sql:
        if char == '\\' and not escaped:
            escaped = True
            continue
        if char == "'" and not in_double_quote and not escaped:
            in_single_quote = not in_single_quote
        elif char == '"' and not in_single_quote and not escaped:
            in_double_quote = not in_double_quote
        elif char == ';' and not in_single_quote and not in_double_quote:
            semicolon_count += 1
        escaped = False

    # Allow trailing semicolon at the end of the query, but block multiple statements
    cleaned = sql.strip().rstrip(';')
    return ';' in cleaned

def validate_select_query(query: str):
    """
    Validates user SQL query.
    Returns (is_valid: bool, error_msg: str, cleaned_query: str)
    """
    if not query or not query.strip():
        return False, "Query cannot be empty.", ""

    # Step 1: Strip SQL comments
    clean_sql = remove_sql_comments(query)
    if not clean_sql:
        return False, "Query contains no executable statements after stripping comments.", ""

    # Step 2: Check for multiple statements
    if check_multiple_statements(clean_sql):
        return False, "Multiple SQL statements separated by semicolons are not permitted.", ""

    # Clean trailing semicolon
    clean_sql = clean_sql.rstrip(';').strip()

    # Step 3: Check starting keyword
    tokens = clean_sql.split()
    first_word = tokens[0].upper()

    if first_word not in ("SELECT", "WITH"):
        return False, f"Forbidden statement type: '{first_word}'. Only SELECT queries are allowed.", ""

    # Step 4: Token-level keyword verification (case-insensitive keyword matching)
    # Remove string literals before keyword scanning so text inside quotes (e.g. WHERE msg = 'DELETE') won't trigger false positives
    sql_without_strings = re.sub(r"'[^']*'", "''", clean_sql)
    sql_without_strings = re.sub(r'"[^"]*"', '""', sql_without_strings)

    words = re.findall(r'\b[A-Za-z_]+\b', sql_without_strings)
    upper_words = [w.upper() for w in words]

    for kw in DISALLOWED_KEYWORDS:
        if kw in upper_words:
            return False, f"Security Violation: Disallowed SQL keyword '{kw}' detected. Only read-only SELECT queries are allowed.", ""

    # Step 5: Disallow SQLite dangerous functions
    if re.search(r'\bload_extension\b', clean_sql, re.IGNORECASE):
        return False, "Security Violation: Function 'load_extension' is prohibited.", ""

    return True, "", clean_sql
