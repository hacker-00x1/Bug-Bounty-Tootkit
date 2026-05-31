# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""Information Disclosure — exposed files, secrets, error messages."""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from data.webfuzz import fetch_url

SENSITIVE_PATHS = [
    # Git/VCS
    (".git/HEAD",           "HIGH",     "Git HEAD exposed"),
    (".git/config",         "HIGH",     "Git config exposed"),
    (".git/COMMIT_EDITMSG", "HIGH",     "Git commit message exposed"),
    (".git/logs/HEAD",      "HIGH",     "Git log exposed"),
    (".svn/entries",        "HIGH",     "SVN repository exposed"),
    (".hg/hgrc",            "HIGH",     "Mercurial config exposed"),
    # Env / config
    (".env",                "CRITICAL", ".env — secrets/credentials"),
    (".env.local",          "CRITICAL", ".env.local — secrets"),
    (".env.production",     "CRITICAL", ".env.production — prod secrets"),
    (".env.staging",        "CRITICAL", ".env.staging — staging secrets"),
    (".env.backup",         "CRITICAL", ".env backup — secrets"),
    (".env.bak",            "CRITICAL", ".env.bak — secrets"),
    ("config.php",          "HIGH",     "PHP config exposed"),
    ("configuration.php",   "HIGH",     "Joomla config exposed"),
    ("wp-config.php.bak",   "CRITICAL", "WordPress config backup"),
    ("wp-config.php~",      "CRITICAL", "WordPress config swap file"),
    ("settings.py",         "HIGH",     "Django settings exposed"),
    ("local_settings.py",   "HIGH",     "Django local settings"),
    ("config.yml",          "HIGH",     "YAML config exposed"),
    ("config.yaml",         "HIGH",     "YAML config exposed"),
    ("database.yml",        "HIGH",     "Database credentials"),
    ("database.yaml",       "HIGH",     "Database credentials"),
    ("secrets.yml",         "CRITICAL", "Secrets file"),
    ("secrets.yaml",        "CRITICAL", "Secrets file"),
    ("application.yml",     "HIGH",     "Spring Boot config"),
    ("application.properties","HIGH",   "Spring Boot properties"),
    # Logs
    ("error.log",           "HIGH",     "Error log — stack traces/paths"),
    ("debug.log",           "HIGH",     "Debug log exposed"),
    ("access.log",          "MEDIUM",   "Access log exposed"),
    ("application.log",     "HIGH",     "Application log"),
    ("server.log",          "HIGH",     "Server log"),
    ("logs/error.log",      "HIGH",     "Error log"),
    ("logs/debug.log",      "HIGH",     "Debug log"),
    ("logs/access.log",     "MEDIUM",   "Access log"),
    ("storage/logs/laravel.log","HIGH", "Laravel log"),
    ("var/log/app.log",     "HIGH",     "Application log"),
    # Backups / dumps
    ("backup.sql",          "CRITICAL", "SQL dump"),
    ("backup.zip",          "CRITICAL", "Backup archive"),
    ("backup.tar.gz",       "CRITICAL", "Backup archive"),
    ("backup.tar.bz2",      "CRITICAL", "Backup archive"),
    ("db.sql",              "CRITICAL", "Database dump"),
    ("database.sql",        "CRITICAL", "Database dump"),
    ("dump.sql",            "CRITICAL", "Database dump"),
    ("mysql.sql",           "CRITICAL", "MySQL dump"),
    ("site.zip",            "CRITICAL", "Site archive"),
    ("www.zip",             "CRITICAL", "Web root archive"),
    # PHP info
    ("phpinfo.php",         "HIGH",     "phpinfo() — server internals"),
    ("info.php",            "HIGH",     "PHP info page"),
    ("test.php",            "MEDIUM",   "PHP test file"),
    ("server-status",       "MEDIUM",   "Apache server-status"),
    ("server-info",         "MEDIUM",   "Apache server-info"),
    (".htaccess",           "MEDIUM",   ".htaccess rules"),
    ("web.config.bak",      "HIGH",     "web.config backup"),
    ("web.config~",         "HIGH",     "web.config swap"),
    # Cloud / credentials
    ("aws_credentials",     "CRITICAL", "AWS credentials"),
    (".aws/credentials",    "CRITICAL", "AWS credentials"),
    ("credentials.json",    "CRITICAL", "Credentials JSON"),
    ("service-account.json","CRITICAL", "GCP service account"),
    ("terraform.tfstate",   "CRITICAL", "Terraform state — infra secrets"),
    ("terraform.tfvars",    "CRITICAL", "Terraform vars — secrets"),
    # CI/CD
    (".travis.yml",         "MEDIUM",   "Travis CI config"),
    (".circleci/config.yml","MEDIUM",   "CircleCI config"),
    ("Jenkinsfile",         "MEDIUM",   "Jenkins pipeline"),
    (".github/workflows/deploy.yml","MEDIUM","GitHub Actions deploy"),
    # Deps
    ("composer.json",       "LOW",      "PHP deps/versions"),
    ("package.json",        "LOW",      "Node deps/versions"),
    ("Gemfile",             "LOW",      "Ruby deps"),
    ("requirements.txt",    "LOW",      "Python deps"),
    ("Pipfile",             "LOW",      "Pipfile"),
    ("poetry.lock",         "LOW",      "Poetry lockfile"),
    # Docker / infra
    ("Dockerfile",          "MEDIUM",   "Dockerfile — infra details"),
    ("docker-compose.yml",  "HIGH",     "docker-compose — may have creds"),
    ("docker-compose.yaml", "HIGH",     "docker-compose — may have creds"),
    (".dockerenv",          "LOW",      "Docker environment marker"),
    ("kubernetes.yml",      "HIGH",     "K8s config"),
    ("k8s.yml",             "HIGH",     "K8s config"),
    # IDE/editor
    (".DS_Store",           "LOW",      ".DS_Store — dir structure"),
    (".idea/workspace.xml", "LOW",      "JetBrains workspace"),
    (".vscode/settings.json","LOW",     "VS Code settings"),
    # Adminer / phpmyadmin
    ("adminer.php",         "HIGH",     "Adminer DB admin exposed"),
    ("adminer-4.7.9.php",   "HIGH",     "Adminer exposed"),
    ("phpmyadmin/index.php","HIGH",     "phpMyAdmin exposed"),
    # Swagger/API docs
    ("swagger.json",        "MEDIUM",   "Swagger/OpenAPI spec"),
    ("swagger.yaml",        "MEDIUM",   "Swagger/OpenAPI spec"),
    ("openapi.json",        "MEDIUM",   "OpenAPI spec"),
]

SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^"\'>\s]{6,})',         "CRITICAL", "Hardcoded password"),
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})',   "CRITICAL", "Hardcoded API key"),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})','CRITICAL', "Hardcoded secret key"),
    (r'AKIA[A-Z0-9]{16}',                                                   "CRITICAL", "AWS Access Key ID"),
    (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9+/]{40})','CRITICAL',"AWS Secret Key"),
    (r'BEGIN RSA PRIVATE KEY',                                              "CRITICAL", "RSA private key"),
    (r'BEGIN OPENSSH PRIVATE KEY',                                          "CRITICAL", "SSH private key"),
    (r'BEGIN EC PRIVATE KEY',                                               "CRITICAL", "EC private key"),
    (r'ghp_[A-Za-z0-9]{36}',                                               "CRITICAL", "GitHub PAT"),
    (r'ghs_[A-Za-z0-9]{36}',                                               "CRITICAL", "GitHub secret"),
    (r'sk-[A-Za-z0-9]{48}',                                                "CRITICAL", "OpenAI API key"),
    (r'AIza[A-Za-z0-9_\-]{35}',                                            "CRITICAL", "Google API key"),
    (r'(?i)(db[_-]?pass(word)?|database[_-]?pass)\s*[=:]\s*["\']?(\S{4,})','HIGH',    "DB password"),
    (r'(?i)(smtp[_-]?pass|mail[_-]?pass)\s*[=:]\s*["\']?(\S{4,})',        "HIGH",     "SMTP password"),
    (r'(?i)(private[_-]?key|rsa private key)',                              "CRITICAL", "Private key material"),
    (r'xox[baprs]-[A-Za-z0-9\-]+',                                         "CRITICAL", "Slack token"),
    (r'(?i)(stripe[_-]?key|stripe[_-]?secret)\s*[=:]\s*["\']?(sk_live_[A-Za-z0-9]+)', "CRITICAL", "Stripe live key"),
]

ERROR_PATTERNS = [
    (r'(?i)(stack trace|traceback|at\s+\w+\.\w+\([\w.]+:\d+\))',           "MEDIUM", "Stack trace exposed"),
    (r'(?i)(ORA-\d{5}|mysql error|sql syntax|pg::)',                        "HIGH",   "DB error in response"),
    (r'(?i)(debug\s*=\s*true|debug_mode\s*=\s*true|APP_DEBUG=true)',        "HIGH",   "Debug mode enabled"),
    (r'(?i)(php (notice|warning|fatal error|parse error):)',                 "MEDIUM", "PHP error exposed"),
    (r'(?i)(exception in thread|unhandled exception|500 internal server)',   "MEDIUM", "Unhandled exception"),
    (r'(?i)/home/\w+/(www|public_html|sites)',                              "LOW",    "Server path disclosed"),
    (r'(?i)(Traceback \(most recent call last\))',                          "MEDIUM", "Python traceback exposed"),
    (r'(?i)(RuntimeException|NullPointerException|ClassNotFoundException)', "MEDIUM", "Java exception exposed"),
]

CVSS = {"CRITICAL": ("9.3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "HIGH":     ("7.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "MEDIUM":   ("5.3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        "LOW":      ("3.7", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N")}


def _check_path(base_url: str, entry: tuple, timeout: int) -> dict | None:
    path, severity, desc = entry
    url = base_url.rstrip("/") + "/" + path
    resp = fetch_url(url, timeout=timeout)
    if not resp or resp.get("status") not in (200, 206):
        return None
    body = resp.get("body") or ""
    if len(body) < 20:
        return None
    score, vector = CVSS.get(severity, ("5.0", ""))
    return {
        "type": "Information Disclosure",
        "severity": severity,
        "url": url,
        "file": path,
        "cvss_score": score,
        "cvss_vector": vector,
        "description": f"{desc} — file '{path}' is publicly accessible",
        "steps_to_reproduce": f"1. curl -s '{url}'\n2. Inspect response for sensitive data.",
        "impact": f"Attacker can access {desc.lower()} directly from the web.",
        "recommendation": "Remove file from web root, or block via nginx/Apache access rules. Rotate any exposed credentials immediately.",
    }


def _check_secrets(base_url: str, timeout: int) -> list[dict]:
    findings = []
    resp = fetch_url(base_url, timeout=timeout)
    if not resp:
        return findings
    body = resp.get("body") or ""
    for pattern, severity, desc in SECRET_PATTERNS:
        if re.search(pattern, body):
            score, vector = CVSS.get(severity, ("9.0", ""))
            findings.append({
                "type": f"Info Disclosure — {desc}",
                "severity": severity,
                "url": base_url,
                "cvss_score": score,
                "cvss_vector": vector,
                "description": f"{desc} found in response body of {base_url}",
                "steps_to_reproduce": f"1. curl -s '{base_url}' | grep -i 'password\\|secret\\|key'\n2. Observe credential material.",
                "impact": "Credential theft enabling account takeover, data breach, or cloud infrastructure compromise.",
                "recommendation": "Remove hardcoded credentials immediately. Use environment variables or a secrets manager (Vault, AWS Secrets Manager).",
            })
    for pattern, severity, desc in ERROR_PATTERNS:
        if re.search(pattern, body):
            score, vector = CVSS.get(severity, ("5.0", ""))
            findings.append({
                "type": f"Info Disclosure — {desc}",
                "severity": severity,
                "url": base_url,
                "cvss_score": score,
                "cvss_vector": vector,
                "description": f"{desc} in response from {base_url}",
                "steps_to_reproduce": f"1. Visit {base_url}\n2. Observe error/debug output in page source.",
                "impact": "Internal paths, software versions, and technology stack disclosed to attackers.",
                "recommendation": "Disable debug mode in production. Use generic error pages. Log errors server-side only.",
            })
    return findings


def run(base_url: str, domain: str = "", timeout: int = 4, threads: int = 25, **kwargs) -> dict:
    findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_check_path, base_url, p, timeout) for p in SENSITIVE_PATHS]
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                findings.append(r)
    findings.extend(_check_secrets(base_url, timeout))
    findings.sort(key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f["severity"], 4))
    return {
        "findings": findings,
        "summary": {
            "paths_checked": len(SENSITIVE_PATHS),
            "exposed_files": len([f for f in findings if f["type"] == "Information Disclosure"]),
            "secrets_found": len([f for f in findings if "—" in f["type"]]),
            "total_findings": len(findings),
        },
    }


if __name__ == "__main__":
    pass
