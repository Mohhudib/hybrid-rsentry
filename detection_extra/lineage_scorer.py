import psutil, hashlib, os

KNOWN_GOOD_BINARIES = {"rsync", "tar", "cp", "mv", "python3", "python"}
KNOWN_GOOD_HASHES = set()  # load from file later

def score_lineage(pid: int) -> int:
    score = 0
    try:
        proc = psutil.Process(pid)
        parents = [p.name() for p in proc.parents()]
        exe = proc.exe()

        # known good binary = less suspicious
        if proc.name() in KNOWN_GOOD_BINARIES:
            score -= 20

        # suspicious parent chains
        if "PowerShell" in " ".join(parents):
            score += 40
        if not parents:
            score += 20

        # suspicious spawn locations
        if "/tmp/" in exe:
            score += 50
        if "/Downloads/" in exe:
            score += 30

        # unknown binary hash = suspicious
        h = hashlib.sha256(open(exe, "rb").read()).hexdigest()
        if h not in KNOWN_GOOD_HASHES:
            score += 25

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        score += 30  # can't read = suspicious

    return max(0, min(100, score))
