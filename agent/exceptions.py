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
    ".gpg", ".pgp", ".asc", ".enc", ".key", ".pem", ".crt", ".der",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg",
    ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".flac", ".ogg", ".wav",
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ttf", ".otf", ".woff",
    ".iso", ".img", ".deb", ".rpm", ".apk",
    ".pyc", ".pyo", ".so", ".o", ".a", ".dll", ".exe",
    ".sqlite", ".db", ".sqlite3",
}


def is_whitelisted_path(path: str) -> bool:
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
    if is_whitelisted_path(path):
        return True
    if process_name and is_whitelisted_process(process_name):
        return True
    return False
