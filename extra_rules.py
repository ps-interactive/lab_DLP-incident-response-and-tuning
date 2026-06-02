"aws_access_key": {
    "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "severity": "high"
},
"database_password": {
    "pattern": re.compile(r"\b(db_password|database_password|password)\s*[:=]\s*['\"]?[^'\"]{8,}['\"]?"),
    "severity": "high"
}
