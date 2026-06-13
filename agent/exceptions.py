"""
exceptions.py — Whitelist/exception rules to suppress false positives.
Covers Kali Linux tools, browsers, system processes, and high-entropy file types.
"""
import os
from pathlib import Path

WHITELISTED_PROCESSES = {
    "celery", "uvicorn", "gunicorn", "python3", "python",
    "apt", "apt-get", "dpkg", "apt-cache", "apt-mark",
    "pip", "pip3",
    "git", "git-lfs",
    "npm", "node", "nodejs",
    "docker", "dockerd", "containerd",
    "firefox", "firefox-esr", "chromium", "chrome", "brave",
    "code", "code-server", "vim", "nvim", "nano", "gedit",
    "zip", "unzip", "tar", "gzip", "gunzip", "bzip2", "xz", "7z", "7za",
    "gpg", "gpg2", "openssl",
    "systemd", "journald", "rsyslog", "cron", "crond",
    "update-notifier", "packagekitd",
}

WHITELISTED_PATH_PREFIXES = [
    os.path.expanduser("~/.cache/"),
    os.path.expanduser("~/.mozilla/"),
    os.path.expanduser("~/.config/google-chrome/"),
    os.path.expanduser("~/.config/chromium/"),
    "/var/cache/apt/",
    "/var/lib/apt/",
    "/var/lib/dpkg/",
    "/var/lib/docker/",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/proc/",
    "/sys/",
    "/run/",
    os.path.expanduser("~/.local/lib/"),
    os.path.expanduser("~/.local/share/"),
    "/usr/lib/python",
    "/usr/local/lib/python",
]

WHITELISTED_EXTENSIONS = {
    ".zip", ".gz", ".bz2", ".xz", ".zst", ".7z", ".rar", ".tar",
    ".tgz", ".tbz2", ".txz",
    ".gpg", ".pgp", ".asc", ".key", ".pem", ".crt", ".der",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg",
    ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".flac", ".ogg", ".wav",
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ttf", ".otf", ".woff",
    ".iso", ".img", ".deb", ".rpm", ".apk",
    ".pyc", ".pyo", ".so", ".o", ".a",
    # .exe / .dll removed — not native Linux extensions
    ".sqlite", ".db", ".sqlite3",
}


# ── Smart temp-dir filter ─────────────────────────────────────────
# Temp dirs بتضل whitelisted، إلا لو الملف بامتداد بستهدفه الـ ransomware
TEMP_DIR_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")

SUSPICIOUS_EXTENSIONS_IN_TEMP = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".odt", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp4", ".mp3", ".wav",
    ".db", ".sqlite", ".sqlite3", ".csv", ".json", ".xml",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".py", ".js", ".ts", ".c", ".cpp", ".h", ".java", ".go", ".rs",
    ".key", ".pem", ".crt", ".kdbx",
}


def _is_suspicious_in_temp(path: str) -> bool:
    """True if path is in a temp dir AND has a ransomware-targeted extension."""
    if not path.startswith(TEMP_DIR_PREFIXES):
        return False
    return Path(path).suffix.lower() in SUSPICIOUS_EXTENSIONS_IN_TEMP


def is_whitelisted_path(path: str) -> bool:
    # Smart override: temp dir + suspicious ext ← never whitelisted
    if _is_suspicious_in_temp(path):
        return False
    for prefix in WHITELISTED_PATH_PREFIXES:
        if path.startswith(prefix):
            return True
    ext = Path(path).suffix.lower()
    if ext in WHITELISTED_EXTENSIONS:
        return True
    return False


def is_whitelisted_process(process_name: str) -> bool:
    return process_name.lower() in WHITELISTED_PROCESSES


def is_whitelisted(path: str, process_name: str = "") -> bool:
    # Strong override: suspicious-in-temp مش whitelisted حتى لو الـ process معروف
    if _is_suspicious_in_temp(path):
        return False
    if is_whitelisted_path(path):
        return True
    if process_name and is_whitelisted_process(process_name):
        return True
    return False
