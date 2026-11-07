"""ReconX configuration. Override any value with an environment variable or a .env file."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _load_env_file():
    env = BASE_DIR / ".env"
    if env.is_file():
        for line in env.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_env_file()


def _num(name, default, cast=float):
    try:
        return cast(os.getenv(name, default))
    except ValueError:
        return default


APP_NAME = "ReconX"
VERSION = "1.0.0"
HOST = "127.0.0.1"                       # local only - never bind to 0.0.0.0
PORT = _num("RECONX_PORT", 5000, int)
DATABASE_PATH = os.getenv("RECONX_DB", str(BASE_DIR / "database" / "reconx.db"))
REPORTS_DIR = BASE_DIR / "reports"

# Timeouts (seconds)
DNS_TIMEOUT = _num("RECONX_DNS_TIMEOUT", 5)
HTTP_TIMEOUT = _num("RECONX_HTTP_TIMEOUT", 8)
SSL_TIMEOUT = _num("RECONX_SSL_TIMEOUT", 6)
CRTSH_TIMEOUT = _num("RECONX_CRTSH_TIMEOUT", 25)

# Authorised port assessment limits
PORT_CONNECT_TIMEOUT = _num("RECONX_PORT_TIMEOUT", 1.5)
PORT_MAX_WORKERS = _num("RECONX_PORT_WORKERS", 5, int)
SAFE_PORTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

# DNS TXT ownership verification
VERIFY_LABEL = "_reconx"
VERIFY_PREFIX = "reconx-verification="

USER_AGENT = f"ReconX/{VERSION} (passive security research; local student project)"
MAX_ACTIVE_SCANS = 3
