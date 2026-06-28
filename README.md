# Hacker00X1 — Bug Bounty ToolKit

Automated reconnaissance and vulnerability scanner for bug bounty hunters. Performs full recon, port scanning, crawling, and 20+ vulnerability checks in a parallel 4-phase pipeline, then generates HTML, JSON, OWASP, and HackerOne-ready markdown reports.

---

## Quick Start

```bash
# 1. Install dependencies (once)
pip install -r requirements.txt

# 2. Run against a target
python bb.py example.com
```

Reports are saved to `reports/` by default.

---

## Usage

```
python bb.py [TARGET] [OPTIONS]
python bb.py --target-list targets.txt [OPTIONS]
```

### Examples

```bash
# Full scan
python bb.py example.com

# Full URL with extended port range
python bb.py https://api.example.com --ports extended

# Generate all report types
python bb.py example.com --report-owasp --export-h1

# H1 triage mode — only CRITICAL/HIGH confirmed findings, HackerOne report auto-included
python bb.py example.com --triage

# Skip slow modules for a fast scan
python bb.py example.com --skip-ports --skip-subdomains --skip-crawl

# Scan a list of targets, output HackerOne reports for each
python bb.py --target-list targets.txt -o /tmp/reports --export-h1

# Custom output directory and threads
python bb.py example.com -o /tmp/myreports --threads 20 --timeout 8

# Quiet mode — minimal console output
python bb.py example.com -q --json-only

# Resume an interrupted scan from the last completed phase
python bb.py example.com --resume

# List all in-progress checkpoints across all targets
python bb.py --list-checkpoints
```

### targets.txt format

```
# Lines starting with # are comments and are skipped
example.com
sub.example.com
https://api.example.com

# blank lines are also skipped
staging.example.com
```

---

## All Flags

### Core

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `TARGET` | | — | Domain or full URL to scan |
| `--target-list` | `-T` | — | File with one target per line |
| `--config` | `-c` | `config.yaml` | Custom YAML config file |
| `--output-dir` | `-o` | `reports/` | Output directory for reports |
| `--threads` | `-t` | 30 | Concurrent threads |
| `--timeout` | | 4 | Request timeout (seconds) |
| `--quiet` | `-q` | off | Minimal console output |

### Reports

| Flag | Description |
|------|-------------|
| `--no-report` | Skip saving any report |
| `--json-only` | Save JSON report only (skip HTML) |
| `--report-owasp` | Generate OWASP Top 10 compliance HTML report |
| `--export-h1` | Generate HackerOne-ready markdown report |

### H1 Triage Mode

| Flag | Description |
|------|-------------|
| `--triage` | Keep only CRITICAL/HIGH findings that are **confirmed** or **likely**. Automatically enables `--export-h1`. Use immediately before submitting to HackerOne to cut noise and focus on high-signal bugs. |

### Resume & Checkpoints

| Flag | Description |
|------|-------------|
| `--resume` | Resume an interrupted scan from the last completed phase. Skips all network I/O for finished phases and picks up where the scan crashed or was killed. |
| `--list-checkpoints` | Display all in-progress scan checkpoints with phase status, progress bar, age, and start time — then exit. |

### Scan Control

| Flag | Description |
|------|-------------|
| `--ports` | Port range: `common` (default), `extended`, or `all` |
| `--ignore-ssl` | Ignore SSL certificate errors |
| `--skip-validate` | Skip post-scan finding re-validation (faster, more false positives) |
| `--wordlist-subdomains` | Custom subdomain brute-force wordlist |
| `--wordlist-dirs` | Custom directory fuzzing wordlist |
| `--scope-file` `-s` | JSON/YAML scope file — strips out-of-scope findings from all reports |

### Skip Flags

| Flag | Skips |
|------|-------|
| `--skip-waf` | WAF & rate-limit fingerprinting |
| `--skip-ports` | Port scanning |
| `--skip-subdomains` | Subdomain enumeration |
| `--skip-dirfuzz` | Directory fuzzing |
| `--skip-vulns` | Core vulnerability checks |
| `--skip-takeover` | Subdomain takeover detection |
| `--skip-xss-gen` | Context-aware XSS analysis |
| `--skip-js` | JavaScript file analysis |
| `--skip-cors-deep` | Deep CORS misconfiguration scan |
| `--skip-smuggle` | HTTP request smuggling detection |
| `--skip-redirect` | Open redirect chain analysis |
| `--skip-crawl` | Passive link crawler |
| `--skip-owasp` | OWASP Top 10 checks |
| `--skip-sqli` | SQL injection module |
| `--skip-auth` | Authentication testing |
| `--skip-pathtraversal` | Path traversal / LFI |
| `--skip-cmdinject` | Command injection |
| `--skip-bizlogic` | Business logic vulnerabilities |
| `--skip-infodisclosure` | Information disclosure |
| `--skip-accesscontrol` | Access control / IDOR |
| `--skip-fileupload` | File upload vulnerabilities |
| `--skip-raceconditions` | Race condition detection |
| `--skip-ssrf` | SSRF testing |
| `--skip-xxe` | XXE injection |
| `--skip-nosqli` | NoSQL injection |
| `--skip-apitest` | API endpoint testing |
| `--skip-webcache` | Web cache deception/poisoning |

### Crawl Options

| Flag | Default | Description |
|------|---------|-------------|
| `--crawl-depth` | 2 | Maximum crawl depth |
| `--crawl-pages` | 60 | Maximum pages to crawl |
| `--crawl-scope` | `domain` | `domain` = same host only, `subdomains` = include all subdomains |
| `--crawl-delay` | 0 | Milliseconds between requests to same host |
| `--no-robots` | off | Ignore `robots.txt` |

---

## Scan Pipeline

Each target runs through a **parallel 4-phase pipeline**. Phases that are independent fire simultaneously, cutting total scan time dramatically compared to a sequential approach.

```
IP Resolution
  ↓
╔══════════════════════════════════════════════════════════════════╗
║  PHASE 1 — Parallel                                             ║
║  WAF fingerprinting · DNS records · Subdomain enum · Port scan  ║
╚══════════════════════════════════════════════════════════════════╝
  ↓
╔══════════════════════════════════════════════════════════════════╗
║  PHASE 2 — Sequential                                           ║
║  Homepage fetch · Technology detection · Directory fuzzing      ║
╚══════════════════════════════════════════════════════════════════╝
  ↓
╔══════════════════════════════════════════════════════════════════╗
║  PHASE 3 — Parallel                                             ║
║  Passive crawler · Subdomain takeover detection                 ║
╚══════════════════════════════════════════════════════════════════╝
  ↓
╔══════════════════════════════════════════════════════════════════╗
║  PHASE 4 — All modules simultaneously (20+ threads)             ║
║  Core vulns · JS analysis · Deep CORS · HTTP smuggling          ║
║  XSS generation · Open redirects · OWASP Top 10                 ║
║  SQLi · Auth · Path traversal · Cmd injection · Biz logic       ║
║  Info disclosure · Access control · File upload                 ║
║  Race conditions · SSRF · XXE · NoSQLi · API testing            ║
║  Web cache deception/poisoning                                  ║
╚══════════════════════════════════════════════════════════════════╝
  ↓
Post-scan validation   (re-tests each finding, removes false positives)
  ↓
Report generation      JSON + HTML + OWASP HTML + HackerOne MD
```

---

## Resume & Checkpoints

Long scans against complex targets can take 30+ minutes. If a scan crashes, loses network, or is killed mid-run, `--resume` lets you pick up exactly where it stopped — with zero repeated network I/O.

### How it works

After each phase completes, its full results are serialised to:

```
{output-dir}/.checkpoints/{domain}.json
```

On a resumed run, completed phases are loaded from disk and their work is skipped entirely. Only the remaining phases actually run.

### Workflow

```bash
# Scan crashes during Phase 4
python bb.py example.com

# Resume — Phases 1/2/3 load from disk, Phase 4 re-runs from scratch
python bb.py example.com --resume
```

Console output on resume:

```
⏩ Resume Mode ──────────────────────────────────────────
  Checkpoint : reports/.checkpoints/example_com.json
  Created    : 2026-05-31T10:02:44
  Completed  : p1, p2, p3

  Skipping completed phases — running only remaining work.

━━ Phase 1/4 — ⏩ loaded from checkpoint
━━ Phase 2/4 — ⏩ loaded from checkpoint
━━ Phase 3/4 — ⏩ loaded from checkpoint
━━ Phase 4/4 — Parallel vulnerability scan (22 modules)
```

The checkpoint file is **automatically deleted** when a scan completes successfully, so stale data never interferes with future fresh scans.

### Listing checkpoints

```bash
python bb.py --list-checkpoints
# or with a custom output dir:
python bb.py --list-checkpoints -o /tmp/reports
```

Displays a table of all in-progress scans:

```
╭─ ⏸  Checkpoint Registry  ─  3 in-progress scans ────────────────────────╮
│  Scans that were interrupted mid-run.                                     │
│  Resume any with: python bb.py <domain> --resume                          │
╰───────────────────────────────────────────────────────────────────────────╯

 #   Domain              Phases                          Progress   Last seen
 1   example.com         ● Recon ● Web ● Crawl ○ Vulns  ██████░░   2h 14m ago
 2   api.target.io       ● Recon ● Web ○ Crawl ○ Vulns  ████░░░░   45m ago
 3   staging.app.com     ● Recon ○ Web ○ Crawl ○ Vulns  ██░░░░░░   8d ago
```

Green dots `●` = phase complete and saved. Dim `○` = not yet run.

---

## H1 Triage Mode (`--triage`)

Filters the scan output down to only the bugs most likely to be accepted by HackerOne:

- Keeps only **CRITICAL** and **HIGH** severity findings
- Keeps only findings with **confirmed** or **likely** confidence
- Auto-enables `--export-h1` (the HackerOne markdown report is always generated)
- Prints a green summary panel at the end with actionable counts

```bash
# Recommended pre-submission workflow
python bb.py example.com --triage
```

Use after a full scan when you're ready to write up bugs — no noise, no low-confidence speculative findings.

---

## Report Types

| File | Generated when |
|------|---------------|
| `<target>_<ts>.json` | Always (unless `--no-report`) |
| `<target>_<ts>.html` | Always unless `--json-only` |
| `<target>_<ts>_owasp.html` | `--report-owasp` flag |
| `<target>_<ts>_hackerone.md` | `--export-h1` or `--triage` |

### HackerOne Report (`--export-h1` / `--triage`)

Generates a ready-to-submit markdown file containing:
- Executive summary table (Critical / High / Medium / Low / Info counts)
- Reconnaissance overview (WAF, subdomains, open ports, technologies)
- One submission block per Critical/High/Medium finding with:
  - **Summary** and **Severity** (mapped to HackerOne's rating scale)
  - **Weakness** — auto-mapped CWE ID (covers 25+ vulnerability types)
  - **Affected Asset**, **Steps to Reproduce**, **Impact**, **Recommended Fix**
  - **Supporting Material** (payload, parameter, method, etc.)
- Disclosure policy reminder

---

## Multi-Target Mode

When `--target-list` is used, each target runs the full pipeline independently, then a comparison table is printed at the end showing Critical / High / Medium / Low counts, duration, and report types generated for every target side by side.

---

## Configuration

Edit `config.yaml` to set persistent defaults for threads, timeout, port lists, DNS record types, and more. CLI flags always override config file values.

---

## Requirements

```
requests>=2.31.0
dnspython>=2.4.2
rich>=13.7.0
click>=8.1.7
pyyaml>=6.0.1
urllib3>=2.1.0
beautifulsoup4>=4.12.2
lxml>=5.1.0
```

Install with: `pip install -r requirements.txt`

Python 3.10+ required.

---

## Legal

Only scan targets you own or have explicit written permission to test. Unauthorized scanning may violate computer crime laws. Always follow the program's responsible disclosure policy before submitting reports.
