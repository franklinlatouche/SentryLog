---
tags: [projects, sentrylog, cybersecurity, linux]
---

# SentryLog

**A lightweight SIEM (Security Information and Event Management) tool for Linux servers.**

SentryLog reads server log files, normalizes them into structured events,
runs detection rules against those events, and produces security alerts.
It is designed for small-to-medium environments where a full enterprise SIEM
(Splunk, Elastic SIEM, etc.) would be overkill.

```
                          SentryLog Pipeline

  Log Files              Parsers             Detection Engine          Output
 +-----------+      +---------------+      +------------------+    +-----------+
 | auth.log  |----->| Auth parser   |--+   |  Single-event    |--->| Console   |
 +-----------+      +---------------+  |   |  (pattern match) |    | (Rich)    |
                                       |   +------------------+    +-----------+
 +-----------+      +---------------+  |   +------------------+    +-----------+
 | access.log|----->| Apache parser |--+-->|  Threshold       |--->| JSON file |
 +-----------+      +---------------+  |   |  (sliding window)|    | (.jsonl)  |
                                       |   +------------------+    +-----------+
 +-----------+      +---------------+  |   +------------------+    +-----------+
 | *.log     |----->| Auto-detect   |--+   |  Correlation     |--->| Dashboard |
 +-----------+      +---------------+      |  (event sequence)|    | (Flask)   |
                           |               +------------------+    +-----------+
                           v                        |
                     +-----------+                  v
                     |  SQLite   |<----- alerts stored here too
                     |  Database |
                     +-----------+
```


## What Does It Do?

SentryLog answers the question: **"Is someone attacking my server right now?"**

It works by:

1. **Parsing** log files (SSH auth logs, Apache/Nginx access logs) into a
   common format
2. **Storing** every event in a local SQLite database for querying
3. **Scanning** events against YAML detection rules that describe attack patterns
4. **Alerting** when it finds suspicious activity, with severity levels and
   MITRE ATT&CK technique references

Out of the box it ships with **36 detection rules** covering:

- SSH brute force attacks and credential stuffing
- User enumeration attempts
- Successful login after brute force (credential compromise)
- Privilege escalation via sudo (root shell, sensitive file reads)
- Known CVE exploits: Log4Shell, Shellshock, Spring4Shell, Apache Struts, PHP-CGI
- SQL injection, XSS, and path traversal in web requests
- OS command injection and SSRF attempts
- Web scanner/recon probing (sqlmap, nikto, nmap, dirbuster, etc.)
- Sensitive file exposure (.env, .git, backups, wp-config)
- Webshell upload/access detection
- Coordinated recon-then-exploit attack chains
- Suspicious sudo usage (wget, curl, netcat, base64, package installs)


## Quick Start

### Requirements

- Python 3.10 or later
- Linux (tested on Ubuntu 24.04)
- ~50 MB disk space

### Install

**Standard install** (project on a native Linux filesystem, such as ext4 or btrfs):

```bash
git clone https://github.com/youruser/sentrylog.git
cd sentrylog
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

**FAT32/exFAT filesystem** (USB drive, Windows-shared partition): FAT32 does
not support symlinks, so the venv must live on a local Linux filesystem:

```bash
# Create venv on local disk, point it at the USB project
python3 -m venv ~/sentrylog-venv
source ~/sentrylog-venv/bin/activate
pip install -e /path/to/SentryLog   # path to your clone of this repo
```

Or with development dependencies (pytest, ruff):

```bash
pip install -e ".[dev]"
```

### Verify the Install

```bash
sentrylog --help
```

Expected output starts with `Usage: sentrylog [OPTIONS] COMMAND [ARGS]...` and
lists subcommands (`ingest`, `scan`, `query`, `demo`, `rules`). If the command
is not found, the venv is not active. Run `source .venv/bin/activate` (or
`source ~/sentrylog-venv/bin/activate` for the FAT32 setup) first.

> **Note:** The `sentrylog` command is only available while the virtual
> environment is active. Run the activate command in each new shell session.
> `pip install -e .` must be run from the project root (where `pyproject.toml`
> lives).

### Run the Demo

The fastest way to see SentryLog in action. This generates realistic log files
with embedded attack patterns, ingests them, runs all detection rules, and
displays the results:

```bash
sentrylog demo
```

Generate a PDF report alongside the demo output:

```bash
sentrylog demo --report
```

You will see colored output like this:

```
1. Generated demo logs:
   auth.log:   97 lines
   access.log: 236 lines

2. Ingested 333 events into database

3. Loaded 36 detection rules

4. Detection complete -- 107 alerts generated

 Alert Summary
+----------+-------+
| Severity | Count |
+----------+-------+
| CRITICAL |     4 |
| HIGH     |    22 |
| MEDIUM   |    81 |
+----------+-------+
```

No real logs, no configuration, no external services needed.


## Usage

### Ingest Log Files

Parse log files and store events in the database:

```bash
# Single file (may need sudo or a copy if the file isn't readable)
sentrylog ingest /var/log/auth.log

# If permission denied, copy first:
sudo cp /var/log/auth.log ~/SentryLog/data/auth.log
sudo chown $USER:$USER ~/SentryLog/data/auth.log
sentrylog ingest ~/SentryLog/data/auth.log

# Entire directory (auto-detects log format per file)
sentrylog ingest /var/log/

# Force a specific parser
sentrylog ingest /var/log/auth.log --parser authlog
```

SentryLog auto-detects the log format by sampling the first 20 lines. Supported
formats:

| Format    | Example Source                     | What It Parses                        |
|-----------|-----------------------------------|---------------------------------------|
| `authlog` | `/var/log/auth.log`, `secure`     | SSH logins, sudo, PAM sessions        |
| `apache`  | Apache/Nginx `access.log`         | HTTP requests, attack payloads in URLs|
| `auto`    | *(default)* any of the above      | Tries all parsers, picks best match   |

The `authlog` parser handles both traditional BSD syslog timestamps
(`Mar 10 06:42:12`) and RFC 3339 / ISO 8601 timestamps
(`2026-03-08T03:15:22.123456+00:00`) used by Ubuntu 24.04+ and newer rsyslog
configurations.

### Typical Workflow

SentryLog uses a two-step workflow: first **ingest** logs into the database,
then **scan** the database with detection rules. The `demo` command does both
automatically.

```
  sentrylog ingest <file>     →  logs parsed into SQLite
  sentrylog scan              →  rules run against stored events → alerts
  sentrylog query alerts      →  view generated alerts
```

### Run Detection

Scan all stored events against the detection rules:

```bash
sentrylog scan
```

Specify a custom rules directory:

```bash
sentrylog scan --rules-dir /path/to/my/rules
```

Write alerts to a JSON lines file:

```bash
sentrylog scan --alert-file alerts.jsonl
```

Generate a PDF report (named `sentrylog_report_MM-DD-YYYY.pdf`):

```bash
sentrylog scan --report

# Or specify a custom filename:
sentrylog scan --report-file /path/to/report.pdf
```

The PDF includes an executive summary, severity breakdown, top attacking IPs,
top triggered rules, MITRE ATT&CK coverage, and full alert details grouped by
severity.

### Query Events and Alerts

```bash
# Recent events
sentrylog query events

# Filter by IP address
sentrylog query events --ip 203.0.113.42

# Filter by severity
sentrylog query events --severity high

# Filter by action type
sentrylog query events --action auth_failure

# Show alerts
sentrylog query alerts

# Only unacknowledged alerts
sentrylog query alerts --unacked

# Limit results
sentrylog query events --limit 200
```

### Manage Rules

```bash
# List all loaded rules
sentrylog rules list

# Validate rule files (check for errors before deploying)
sentrylog rules validate rules/
sentrylog rules validate rules/my_new_rule.yml
```

### Verbose Output

Add `-v` for INFO-level logs or `-vv` for full DEBUG output. Useful for
troubleshooting why a rule did or didn't fire.

> **Important:** The `-v`/`-vv` flag must go **before** the subcommand, not
> after. This is because it is defined on the top-level `sentrylog` group.

```bash
# Correct:
sentrylog -v scan
sentrylog -vv ingest /var/log/auth.log --parser authlog

# Wrong (will error):
sentrylog scan -v
sentrylog ingest /var/log/auth.log -vv
```

Example verbose output:

```
17:35:52 INFO    sentrylog.storage.db: Connected to database: sentrylog.db
17:35:52 DEBUG   sentrylog.parsers.auto: Parser authlog scored 1.00 for auth.log
17:35:52 INFO    sentrylog.parsers.auto: Auto-detected authlog parser for auth.log (score=1.00)
17:35:54 INFO    sentrylog.parsers.base: Parsed auth.log: 18266 events, 0 skipped (authlog parser)
17:35:57 INFO    sentrylog.storage.db: Inserted 18266 events into database
```

### Other Options

```bash
# Use a specific database file
sentrylog --db /path/to/my.db query events

# Use a specific config file
sentrylog --config /path/to/sentrylog.yml scan
```

> **Note:** Global options (`--db`, `--config`, `-v`) all go **before** the
> subcommand. Subcommand-specific options (`--parser`, `--limit`, `--ip`)
> go after.


## Detection Rules

Rules are written in YAML and live in the `rules/` directory. SentryLog
supports three rule types, each suited to a different kind of threat:

### Single-Event Rules

Match one event at a time. Good for things that are suspicious on their own.

```
  Event Stream:    ... [normal] [normal] [sudo /bin/bash] [normal] ...
                                              |
                                         Rule matches!
                                              |
                                              v
                                        ALERT: sudo_to_root_shell
```

Example rule file:

```yaml
name: sqli_attempt
type: single
severity: high
description: SQL injection attempt detected in HTTP request
mitre_tags:
  - "T1190"
conditions:
  - field: action
    operator: equals
    value: sqli_attempt
```

### Threshold Rules

Count events in a sliding time window. Good for attacks that are only
meaningful in volume (one failed login is normal, fifty in a minute is not).

```
  Window: 120 seconds
  Threshold: 5 events

  Time --->  [fail] [fail] [fail] [fail] [fail]
              t=0    t=15   t=30   t=45   t=60
              |_________________________________|
                     5 failures in 60s
                            |
                            v
                   ALERT: ssh_brute_force
```

Example rule file:

```yaml
name: ssh_brute_force
type: threshold
severity: high
description: Multiple failed SSH login attempts detected
mitre_tags:
  - "T1110.001"
  - "T1110"
conditions:
  - field: action
    operator: equals
    value: auth_failure
threshold_count: 5
threshold_window: 120
group_by: source_ip
```

`group_by: source_ip` means the count is tracked separately per IP address.
Five failures from 10.0.0.1 won't combine with five from 10.0.0.2.

### Correlation Rules

Detect ordered sequences of events within a time window. Good for multi-stage
attacks where each individual step might look benign, but the sequence reveals
malicious intent.

```
  Window: 600 seconds

  Step 1: auth_failure    Step 2: auth_success
  (brute force)           (attacker got in)

  Time ---> [fail] [fail] [fail] ... [success]
             t=0    t=8    t=16       t=180
             |________________________________|
                 Sequence completed in 180s
                          |
                          v
              ALERT: brute_force_then_success
              Severity: CRITICAL
```

Example rule file:

```yaml
name: brute_force_then_success
type: correlation
severity: critical
description: SSH brute force followed by successful login
mitre_tags:
  - "T1110"
  - "T1078"
conditions: []
group_by: source_ip
correlation_window: 600
sequence:
  - conditions:
      - field: action
        operator: equals
        value: auth_failure
  - conditions:
      - field: action
        operator: equals
        value: auth_success
```

### Condition Operators

Rules use conditions to match event fields. Available operators:

| Operator     | Description                        | Example                         |
|-------------|------------------------------------|---------------------------------|
| `equals`    | Exact string match (default)       | `action equals auth_failure`    |
| `not_equals`| Does not match                     | `user not_equals root`          |
| `contains`  | Substring match (case-insensitive) | `path contains /admin`          |
| `regex`     | Regular expression                 | `user regex ^(root\|admin)$`    |
| `in`        | Value in a list                    | `action in [sqli, xss]`         |
| `gt`        | Greater than (numeric)             | `status gt 499`                 |
| `lt`        | Less than (numeric)                | `status lt 200`                 |

### Matchable Fields

Conditions can reference these event fields:

| Field                      | Description                          |
|---------------------------|--------------------------------------|
| `action`                  | Normalized action (auth_failure, sqli_attempt, etc.) |
| `source_ip`               | IP address of the client/attacker    |
| `user`                    | Username involved                    |
| `source`                  | Parser that produced the event       |
| `severity`                | Event-level severity                 |
| `parsed_fields.path`      | HTTP request path (access logs)      |
| `parsed_fields.status`    | HTTP status code (access logs)       |
| `parsed_fields.method`    | HTTP method (access logs)            |
| `parsed_fields.command`   | sudo command (auth logs)             |
| `parsed_fields.target_user`| sudo target user (auth logs)        |
| `parsed_fields.auth_method`| password or publickey (auth logs)   |
| `parsed_fields.user_agent`| User-Agent header (access logs)      |
| `parsed_fields.referer`   | Referer header (access logs)         |
| `parsed_fields.service`   | Service name like sshd (auth logs)   |
| `parsed_fields.hostname`  | Server hostname (auth logs)          |
| `parsed_fields.pid`       | Process ID (auth logs)               |

### Writing Your Own Rules

1. Create a `.yml` file in the `rules/` directory
2. Validate it: `sentrylog rules validate rules/my_rule.yml`
3. Test it: `sentrylog scan` (or `sentrylog demo` for demo data)

To disable a rule without deleting it, add `enabled: false`.

### MITRE ATT&CK Tags

Each rule can include `mitre_tags` referencing
[MITRE ATT&CK](https://attack.mitre.org/) technique IDs. These appear in alert
output and help map detections to a standardized threat framework. The built-in
rules cover these techniques:

| Tag         | Technique                           | Rule(s)                                |
|-------------|-------------------------------------|----------------------------------------|
| T1190       | Exploit Public-Facing Application   | Log4Shell, Shellshock, Spring4Shell, Struts, SSRF, CGI |
| T1203       | Exploitation for Client Execution   | Log4Shell, Spring4Shell                |
| T1110       | Brute Force                         | SSH brute force, brute force then success |
| T1110.001   | Password Guessing                   | SSH brute force                        |
| T1110.003   | Password Spraying                   | Distributed brute force                |
| T1110.004   | Credential Stuffing                 | Credential stuffing                    |
| T1078       | Valid Accounts                      | Brute force then success, password auth |
| T1078.001   | Default Accounts                    | Root SSH login                         |
| T1548.003   | Sudo and Sudo Caching               | Sudo abuse, unusual commands, rapid burst |
| T1059       | Command and Scripting               | CGI exploits, sudo unusual commands    |
| T1059.004   | Unix Shell                          | Shellshock, OS command injection       |
| T1059.007   | JavaScript                          | XSS attempts                           |
| T1505.003   | Web Shell                           | Webshell access                        |
| T1552.001   | Credentials In Files                | Config file access, API keys in URLs   |
| T1003.008   | /etc/shadow                         | Sudo shadow read                       |
| T1083       | File and Directory Discovery        | Path traversal, config files, backups  |
| T1005       | Data from Local System              | Backup file access                     |
| T1213       | Data from Information Repositories  | Git exposure                           |
| T1027       | Obfuscated Files or Information     | Encoded attack payloads                |
| T1053.003   | Cron                                | CRON service activity                  |
| T1546       | Event Triggered Execution           | Package install via sudo               |
| T1557       | Adversary-in-the-Middle             | SSRF attempts                          |
| T1595       | Active Scanning                     | Recon then exploit                     |
| T1595.002   | Vulnerability Scanning              | Web scanner probes, malicious UAs      |
| T1589.001   | Employee Names (User Enumeration)   | User enumeration, credential stuffing  |


## Project Structure

```
sentrylog/
|-- pyproject.toml                 # Package metadata, dependencies
|-- Makefile                       # install, test, lint, demo shortcuts
|-- config/
|   +-- sentrylog.yml              # Default configuration
|-- rules/                         # YAML detection rules (36 rules)
|   |-- ssh_brute_force.yml        # SSH brute force (threshold)
|   |-- sudo_abuse.yml             # Root shell, shadow reads
|   |-- auth_suspicious.yml        # Root login, credential stuffing, sudo abuse
|   |-- sqli_detection.yml         # SQL injection
|   |-- web_scanning.yml           # Scanner probes, 404 floods, XSS, traversal
|   |-- cve_exploits.yml           # Log4Shell, Shellshock, Spring4Shell, Struts
|   |-- command_injection.yml      # OS injection, SSRF, malicious UAs
|   |-- sensitive_exposure.yml     # .env, .git, backups, webshells, API keys
|   |-- brute_force_success.yml    # Correlation: brute force -> login
|   |-- scan_then_exploit.yml      # Correlation: recon -> exploit
|   +-- invalid_user_enum.yml      # User enumeration (threshold)
|-- src/sentrylog/
|   |-- __main__.py                # python -m sentrylog entry point
|   |-- cli.py                     # Click CLI commands
|   |-- config.py                  # YAML config loader
|   |-- demo.py                    # Demo log generator
|   |-- parsers/
|   |   |-- base.py                # Abstract parser interface
|   |   |-- authlog.py             # Linux auth.log parser
|   |   |-- apache.py              # Apache/Nginx combined log parser
|   |   +-- auto.py                # Auto-detect parser
|   |-- engine/
|   |   |-- rules.py               # YAML rule loader and validator
|   |   +-- detector.py            # Single, threshold, and correlation detectors
|   |-- storage/
|   |   |-- models.py              # NormalizedEvent, Alert, Severity dataclasses
|   |   +-- db.py                  # SQLite database layer (WAL mode)
|   |-- alerting/
|   |   |-- console.py             # Rich terminal alert output
|   |   +-- file.py                # JSON lines file output
|   +-- reporting/
|       +-- pdf.py                 # PDF report generator (fpdf2)
+-- tests/                         # 112 tests (pytest)
    |-- parsers/                   # Parser unit tests (auth, apache, auto-detect)
    |-- engine/                    # Rule, detector, correlation tests
    |-- storage/                   # Database tests
    +-- integration/               # Full pipeline test against demo data
```


## How It Works Internally

### Event Normalization

Every log line, regardless of source format, becomes a `NormalizedEvent`:

```
Raw auth.log line (BSD syslog format):
  "Mar 10 06:42:12 webserver sshd[1234]: Failed password for root from 203.0.113.42 port 54321 ssh2"

Raw auth.log line (RFC 3339 format, Ubuntu 24.04+):
  "2026-03-08T03:15:22.123456+00:00 webserver sshd[1234]: Failed password for root from 203.0.113.42 port 54321 ssh2"

                    |  Auth parser (handles both formats)
                    v

NormalizedEvent:
  timestamp:  2026-03-08 03:15:22
  source:     authlog
  source_ip:  203.0.113.42
  user:       root
  action:     auth_failure
  severity:   medium
  parsed_fields:
    hostname: webserver
    service:  sshd
    pid:      1234
    auth_method: password
```

This normalization means detection rules work the same way regardless of which
log format the data came from.

### Database

Events and alerts are stored in SQLite with WAL (Write-Ahead Logging) mode
enabled. This allows concurrent reads while writing, which matters when the
dashboard reads data while ingestion is running.

The database is a single file (default: `sentrylog.db`). No database server
to install or configure.

### Detection Pipeline

When you run `sentrylog scan`, the engine processes events in chronological
order through all three detector types:

```
  For each event (in time order):
  +-----------------------------------------------+
  |                                                |
  |  1. Single detector:                           |
  |     Does this event match any single rule?     |
  |     If yes -> create alert immediately         |
  |                                                |
  |  2. Threshold detector:                        |
  |     Add to sliding window for matching rules   |
  |     Count events in window per group           |
  |     If count >= threshold -> create alert      |
  |                                                |
  |  3. Correlation detector:                      |
  |     Does this advance any pending sequence?    |
  |     Does this start a new sequence?            |
  |     If sequence completed -> create alert      |
  |     Evict expired partial sequences            |
  |                                                |
  +-----------------------------------------------+
```

Memory is bounded: threshold windows use deques, correlation sequences cap
at 200 partial matches per (rule, group) to prevent unbounded growth.


## Configuration

The default config file is `config/sentrylog.yml`:

```yaml
db_path: sentrylog.db
rules_dir: rules

log_sources:
  - /var/log/auth.log
  - /var/log/apache2/access.log

alert_outputs:
  - console
  - file

# webhook_url: https://hooks.slack.com/services/xxx

dashboard_host: "0.0.0.0"
dashboard_port: 5000
```

All settings can also be overridden via CLI flags (`--db`, `--config`).


## Running on a Local Workstation

The project is stored on a FAT32 USB drive, which does not support symlinks.
Virtual environments must live on a local Linux filesystem.

### What First Run Creates

Running `sentrylog ingest` and `sentrylog scan` from the project directory
creates these files:

```
SentryLog/
├── data/
│   └── sentrylog.db        ← SQLite database (events + alerts)
├── sentrylog_report_MM-DD-YYYY.pdf   ← PDF report (if --report used)
└── alerts.jsonl            ← JSON alert log (if --alert-file used)
```

`sentrylog.db` is relative to your **current working directory** when you run
the command. Always `cd` into the project root first so the database lands in
`data/` where the config expects it, or pass `--db /path/to/my.db` to specify
an explicit path.

### First Time (or After Reboot)

```bash
# 1. Create venv on local disk (persists across reboots)
python3 -m venv ~/sentrylog-venv

# 2. Activate and install
source ~/sentrylog-venv/bin/activate
pip install -e /path/to/SentryLog   # path to your clone of this repo

# 3. Change into project root (controls where sentrylog.db is written)
cd /path/to/SentryLog

# 4. Run the demo to verify everything works (no real logs needed)
sentrylog demo

# 5. Copy auth.log (needs sudo) and scan real logs
sudo cp /var/log/auth.log /tmp/auth.log && sudo chown $USER:$USER /tmp/auth.log
sentrylog ingest /tmp/auth.log --parser authlog
sentrylog scan --report
```

### Returning Sessions (Venv Already Exists)

```bash
source ~/sentrylog-venv/bin/activate
cd /path/to/SentryLog
sudo cp /var/log/auth.log /tmp/auth.log && sudo chown $USER:$USER /tmp/auth.log
sentrylog ingest /tmp/auth.log --parser authlog
sentrylog scan --report
```

### Useful Commands

```bash
sentrylog demo                         # verify install with synthetic data
sentrylog query events --limit 20      # browse stored events
sentrylog query alerts                 # view generated alerts
sentrylog -vv scan --report            # verbose scan with PDF report
sentrylog --db /tmp/alt.db scan        # use a different database file
```

### One-Command Scan Script

`scripts/quick_scan.sh` handles everything automatically: creates the venv if
missing, installs SentryLog if needed, copies auth.log, ingests, scans, and
saves a PDF report.

```bash
# Normal run
bash scripts/quick_scan.sh

# Verbose output
bash scripts/quick_scan.sh -v

# Full debug output
bash scripts/quick_scan.sh -vv
```

The script will prompt for your sudo password (needed to read
`/var/log/auth.log`). The PDF report is saved to the project directory as
`sentrylog_report_MM-DD-YYYY.pdf`.

### Common First-Run Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `command not found: sentrylog` | Venv not active | `source ~/sentrylog-venv/bin/activate` |
| `No module named sentrylog` | Package not installed | `pip install -e /path/to/SentryLog` |
| `bad marshal data` | Stale `.pyc` from different Python version | `find . -type d -name __pycache__ -exec rm -rf {} +` |
| `Permission denied` reading auth.log | Requires root | Copy first: `sudo cp /var/log/auth.log /tmp/auth.log` |
| `sentrylog.db` in wrong directory | Wrong CWD when running command | `cd` into project root first |
| `UnicodeDecodeError` during install | Corrupted file referenced in pyproject.toml | Comment out `readme = "README.md"` in pyproject.toml |


## Deploying to a Server

### First-Time Setup

To run SentryLog on a remote Linux server (e.g., Ubuntu 24.04):

```bash
# 1. Copy the project to the server (run from the project directory)
cd /path/to/SentryLog
scp -r rules/ user@your-server:~/SentryLog/
scp -r src/ user@your-server:~/SentryLog/
scp README.md pyproject.toml Makefile user@your-server:~/SentryLog/

# 2. SSH into the server
ssh user@your-server

# 3. Set up the virtual environment
cd ~/SentryLog
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 4. Copy auth.log (usually requires root permissions)
sudo cp /var/log/auth.log ~/SentryLog/data/auth.log
sudo chown $USER:$USER ~/SentryLog/data/auth.log

# 5. Ingest and scan
sentrylog ingest ~/SentryLog/data/auth.log
sentrylog scan
```

### Updating the Server After Local Changes

When you make changes on your development machine and need to push them to the
server, run these from the project directory on your local machine:

```bash
cd /path/to/SentryLog

# Copy updated source code
scp -r src/ user@your-server:~/SentryLog/

# Copy updated rules
scp -r rules/ user@your-server:~/SentryLog/

# Copy updated docs (optional)
scp README.md user@your-server:~/SentryLog/
```

Then on the server:

```bash
cd ~/SentryLog && source .venv/bin/activate && pip install -e .
```

> **Important:**
> - `scp` commands must be run **one at a time**. Do not combine them on one
>   line with the destination, as line wrapping can cause errors.
> - Make sure you `cd` into the project directory first. `scp` uses relative
>   paths.
> - After updating source files (`src/`), you **must** re-run `pip install -e .`
>   on the server. Rule changes (`rules/`) take effect immediately without
>   reinstalling.
> - If you see stale behavior after updating, clear bytecode cache:
>   `find . -type d -name __pycache__ -exec rm -rf {} +`


## Development

### Run Tests

```bash
make test
# or directly:
pytest --cov=sentrylog --cov-report=term-missing
```

112 tests cover parsers (including both BSD and RFC 3339 timestamp formats),
detection engine, database, rule loading, correlation logic, and full pipeline
integration.

### Lint

```bash
make lint
# or:
ruff check src/ tests/
```

### Project Dependencies

SentryLog has 7 runtime dependencies:

| Package    | Purpose                          |
|-----------|----------------------------------|
| click     | CLI framework                    |
| rich      | Colored terminal output          |
| pyyaml    | YAML rule and config parsing     |
| fpdf2     | PDF report generation            |
| flask     | Dashboard web server             |
| watchdog  | File system monitoring           |
| httpx     | Webhook HTTP client              |

Everything else (SQLite, logging, regex, dataclasses) is Python standard
library.


## Limitations

- **Log formats**: Parses Linux `auth.log` (both BSD syslog and RFC 3339
  timestamp formats) and Apache/Nginx combined access log format. Other formats
  (JSON logs, Windows Event Log, journald binary) are not yet supported.
- **No real-time mode yet**: Currently processes logs in batch. The `watch`
  command for live file tailing is planned but not yet implemented.
- **Single-host**: Designed for one server's logs. No log shipping, no
  distributed collection, no multi-node correlation.
- **SQLite scale**: SQLite handles millions of rows well, but performance
  will degrade with tens of millions of events. For high-volume environments,
  a proper database would be needed.
- **No authentication on dashboard**: The planned Flask dashboard has no
  login or access control. Bind it to localhost or use a reverse proxy with
  auth in production.
- **IPv4 only**: Parser regex patterns match IPv4 addresses. IPv6 addresses
  in logs will not be extracted.
- **No log rotation awareness**: If a log file is rotated (renamed, truncated),
  re-ingesting the new file will not deduplicate against previously ingested
  events.
- **Year inference (BSD format only)**: Traditional BSD syslog timestamps
  (`Mar 10 06:42:12`) lack a year field. The parser assumes the current year,
  which can produce wrong dates around January 1st for logs from the previous
  December. This does not affect RFC 3339 timestamps which include full dates.
- **Alert deduplication**: Threshold and correlation alerts are deduped within
  their time windows, but re-running `sentrylog scan` on the same data will
  produce duplicate alerts in the database.


## Related

- [[Projects_MOC]]

## License

MIT
