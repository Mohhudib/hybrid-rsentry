"""
ai_analyst.py — NVIDIA AI analysis for suspicious events.
Uses meta/llama-3.1-70b-instruct via NVIDIA OpenAI-compatible API.
Rate-limited to 3 seconds between API calls using Redis.
"""
import json
import logging
import os
import re
import time

import redis as redis_lib
from openai import OpenAI

logger = logging.getLogger(__name__)

MODEL_NAME = "meta/llama-3.1-70b-instruct"
_RATE_KEY = "rsentry:nvidia_last_call"
_RATE_DELAY = 3.0  # seconds between NVIDIA API calls

_client = None
_redis = None


def _get_client():
    global _client
    if _client is None:
        api_key = os.getenv("NVIDIA_API_KEY", "")
        if not api_key:
            raise RuntimeError("NVIDIA_API_KEY not set in environment")
        _client = OpenAI(
            base_url="https://integrate.api.nvidia.com/v1",
            api_key=api_key,
        )
    return _client


def _get_redis():
    global _redis
    if _redis is None:
        _redis = redis_lib.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
    return _redis


def _nvidia_rate_limit():
    """Block until at least 3 seconds have passed since the last NVIDIA API call."""
    r = _get_redis()
    while True:
        last = r.get(_RATE_KEY)
        if not last:
            break
        elapsed = time.time() - float(last)
        if elapsed >= _RATE_DELAY:
            break
        wait = _RATE_DELAY - elapsed
        logger.debug("NVIDIA rate limit: waiting %.1fs", wait)
        time.sleep(wait)
    r.set(_RATE_KEY, str(time.time()), ex=30)


SYSTEM_PROMPT = """You are a cybersecurity AI analyst embedded in a ransomware detection system called Hybrid R-Sentry.
You receive detection events from a monitored Linux endpoint and must analyze them.

Respond ONLY with valid JSON in this exact format:
{
  "threat_type": "string (e.g. Ransomware, Cryptominer, Rootkit, Fileless Malware, Benign, Unknown)",
  "technique": "string (e.g. File Encryption, Canary File Access, Entropy Manipulation, Process Injection)",
  "language_or_tool": "string (e.g. Python, Bash, C binary, unknown)",
  "behavior_summary": "string (1-2 sentences plain English explaining what happened)",
  "risk_level": "CRITICAL | HIGH | MEDIUM | LOW",
  "recommendation": "string (1 sentence — what the analyst should do next)",
  "confidence": "HIGH | MEDIUM | LOW"
}

Be concise. Never add text outside the JSON block."""


def build_prompt(event: dict) -> str:
    details = event.get("details", {}) or {}
    ancestors = details.get("ancestors", [])
    reasons = details.get("lineage_reasons", [])
    sub_type = details.get("sub_type", "")

    lines = [
        f"Event type: {event.get('event_type', 'UNKNOWN')}",
        f"Severity: {event.get('severity', 'UNKNOWN')}",
        f"Host: {event.get('host_id', 'unknown')}",
        f"File path: {event.get('file_path', 'none') or 'none'}",
        f"Process: {event.get('process_name', 'unknown')} (PID {event.get('pid', 0)})",
        f"Entropy delta: {event.get('entropy_delta', 0):.3f} (scale 0-8, >3.5 = suspicious)",
        f"Lineage score: {event.get('lineage_score', 0):.1f}/100",
        f"Canary hit: {event.get('canary_hit', False)}",
    ]
    if sub_type:
        lines.append(f"Sub-type: {sub_type}")
    if sub_type == "MARKOV_REPOSITION":
        lines.append("CONTEXT: This is an INTERNAL SYSTEM EVENT. The Markov chain module repositioned canary files to new hotspot locations. This is NOT a threat — classify as Benign with LOW risk.")
    if sub_type == "moved":
        lines.append("CONTEXT: A canary file was moved. This may be the internal Markov chain adaptive repositioner moving canary files to new hotspot locations (a normal defensive operation), OR a real attacker renaming/moving the canary to hide activity. Check if pid==0 and process==unknown — if so, it is the Markov chain.")
    if ancestors:
        lines.append(f"Process ancestors: {' → '.join(str(a) for a in ancestors[:5])}")
    if reasons:
        lines.append(f"Lineage reasons: {', '.join(str(r) for r in reasons[:5])}")
    if details.get("combined_score"):
        lines.append(f"Combined threat score: {details['combined_score']}")

    return "Analyze this detection event:\n\n" + "\n".join(lines)


def analyze_event(event: dict) -> dict:
    """
    Call NVIDIA to analyze a detection event.
    Respects 3-second rate limit via Redis.
    Returns dict with analysis, or {"analysis_failed": True} on error — caller must not publish that.
    """
    try:
        _nvidia_rate_limit()
        client = _get_client()
        prompt = build_prompt(event)
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=500,
        )
        text = response.choices[0].message.content.strip()
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
        return json.loads(text)

    except Exception as exc:
        logger.warning("NVIDIA AI analysis failed: %s", exc)
        return {"analysis_failed": True, "reason": str(exc)[:120]}


def analyze_alert(alert: dict) -> dict:
    """
    Analyze an alert directly (used when manually triggering AI from the Alerts page).
    Builds a prompt from alert fields and calls NVIDIA.
    Returns dict with analysis, or {"analysis_failed": True} on error.
    """
    event = {
        "event_type": alert.get("event_type", "UNKNOWN"),
        "severity": alert.get("severity", "UNKNOWN"),
        "host_id": alert.get("host_id", "unknown"),
        "file_path": alert.get("file_path"),
        "process_name": alert.get("process_name"),
        "pid": alert.get("pid", 0),
        "entropy_delta": alert.get("entropy_delta", 0),
        "lineage_score": alert.get("lineage_score", 0),
        "canary_hit": alert.get("canary_hit", False),
        "details": alert.get("details") or {},
    }
    return analyze_event(event)


def analyze_system_health(recent_events: list[dict]) -> dict:
    """
    Analyze overall system behavior stability from recent events.
    Respects 3-second rate limit via Redis.
    """
    try:
        _nvidia_rate_limit()
        client = _get_client()

        counts = {}
        for e in recent_events:
            counts[e.get("event_type", "UNKNOWN")] = counts.get(e.get("event_type"), 0) + 1

        severities = [e.get("severity") for e in recent_events]
        critical_count = severities.count("CRITICAL")
        high_count = severities.count("HIGH")

        health_prompt = f"""Analyze the overall system health based on recent activity:

Total events (last period): {len(recent_events)}
Event type breakdown: {json.dumps(counts)}
CRITICAL events: {critical_count}
HIGH events: {high_count}
Canary hits: {sum(1 for e in recent_events if e.get('canary_hit'))}
Avg entropy delta: {sum(e.get('entropy_delta', 0) for e in recent_events) / max(len(recent_events), 1):.2f}

Respond with JSON:
{{
  "status": "STABLE | UNDER_ATTACK | ANOMALOUS | RECOVERING",
  "threat_type": "string",
  "behavior_summary": "2-3 sentences describing overall system state",
  "risk_level": "CRITICAL | HIGH | MEDIUM | LOW",
  "recommendation": "string",
  "confidence": "HIGH | MEDIUM | LOW"
}}"""

        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": health_prompt},
            ],
            temperature=0.1,
            max_tokens=500,
        )
        text = response.choices[0].message.content.strip()
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
        return json.loads(text)

    except Exception as exc:
        logger.warning("NVIDIA health analysis failed: %s", exc)
        return {
            "status": "UNKNOWN",
            "threat_type": "—",
            "behavior_summary": f"Health analysis unavailable: {str(exc)[:80]}",
            "risk_level": "UNKNOWN",
            "recommendation": "Check NVIDIA_API_KEY configuration.",
            "confidence": "LOW",
        }
