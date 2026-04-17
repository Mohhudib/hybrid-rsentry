"""
ai_analyst.py — NVIDIA AI analysis for suspicious events and alerts.

Two separate API keys:
  NVIDIA_API_KEY        — used for live event analysis (AI Analyst section)
  NVIDIA_API_KEY_ALERTS — used for on-demand alert analysis (Alerts section)

Each key has its own Redis rate limit key so they don't block each other.
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
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
_RATE_DELAY = 3.0  # seconds between calls per key

# Rate limit Redis keys — one per API key so they're fully independent
_RATE_KEY_EVENTS = "rsentry:nvidia_last_call_events"
_RATE_KEY_ALERTS = "rsentry:nvidia_last_call_alerts"

_client_events = None   # for live event analysis
_client_alerts = None   # for alert analysis
_redis = None

# Lua script for atomic check-and-claim of a rate limit slot.
# Returns '0' if the slot was claimed, or the remaining wait seconds as a string.
_RATE_LIMIT_LUA = """
local key = KEYS[1]
local delay = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local last = redis.call('GET', key)
if last then
    local elapsed = now - tonumber(last)
    if elapsed < delay then
        return tostring(delay - elapsed)
    end
end
redis.call('SET', key, tostring(now), 'EX', 30)
return '0'
"""


def _get_redis():
    global _redis
    if _redis is None:
        _redis = redis_lib.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            decode_responses=True,
        )
    return _redis


def _get_client_events():
    global _client_events
    if _client_events is None:
        key = os.getenv("NVIDIA_API_KEY", "")
        if not key:
            raise RuntimeError("NVIDIA_API_KEY not set in environment")
        _client_events = OpenAI(base_url=NVIDIA_BASE_URL, api_key=key)
    return _client_events


def _get_client_alerts():
    global _client_alerts
    if _client_alerts is None:
        key = os.getenv("NVIDIA_API_KEY_ALERTS", os.getenv("NVIDIA_API_KEY", ""))
        if not key:
            raise RuntimeError("NVIDIA_API_KEY_ALERTS not set in environment")
        _client_alerts = OpenAI(base_url=NVIDIA_BASE_URL, api_key=key)
    return _client_alerts


def _rate_limit(redis_key: str):
    """Block until a rate limit slot is atomically claimed for this key.

    Uses a Lua script so the check-and-set is atomic — two concurrent Celery
    workers cannot both pass simultaneously.
    """
    r = _get_redis()
    script = r.register_script(_RATE_LIMIT_LUA)
    while True:
        wait_str = script(keys=[redis_key], args=[str(_RATE_DELAY), str(time.time())])
        wait = float(wait_str)
        if wait <= 0:
            break
        logger.debug("NVIDIA rate limit (%s): waiting %.1fs", redis_key, wait)
        time.sleep(wait)


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
        lines.append("CONTEXT: A canary file was moved. This may be the internal Markov chain adaptive repositioner (normal defensive operation) OR a real attacker. If pid==0 and process==unknown it is the Markov chain.")
    if ancestors:
        lines.append(f"Process ancestors: {' → '.join(str(a) for a in ancestors[:5])}")
    if reasons:
        lines.append(f"Lineage reasons: {', '.join(str(r) for r in reasons[:5])}")
    if details.get("combined_score"):
        lines.append(f"Combined threat score: {details['combined_score']}")

    return "Analyze this detection event:\n\n" + "\n".join(lines)


def _call_nvidia(client, prompt: str) -> dict:
    """Shared NVIDIA API call. Returns parsed JSON dict."""
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


def analyze_event(event: dict) -> dict:
    """
    Analyze a live detection event using NVIDIA_API_KEY (AI Analyst section).
    Rate-limited independently from alert analysis.
    Returns {"analysis_failed": True} on error — caller must not publish that.
    """
    try:
        _rate_limit(_RATE_KEY_EVENTS)
        result = _call_nvidia(_get_client_events(), build_prompt(event))
        return result
    except Exception as exc:
        logger.warning("NVIDIA event analysis failed: %s", exc)
        return {"analysis_failed": True, "reason": str(exc)[:120]}


def analyze_alert(event: dict) -> dict:
    """
    Analyze an alert on-demand using NVIDIA_API_KEY_ALERTS (Alerts section).
    Rate-limited independently from live event analysis — both keys run in parallel.
    Returns {"analysis_failed": True} on error — caller must not publish that.
    """
    try:
        _rate_limit(_RATE_KEY_ALERTS)
        result = _call_nvidia(_get_client_alerts(), build_prompt(event))
        return result
    except Exception as exc:
        logger.warning("NVIDIA alert analysis failed: %s", exc)
        return {"analysis_failed": True, "reason": str(exc)[:120]}


def _build_health_prompt(recent_events: list[dict]) -> str:
    counts: dict = {}
    for e in recent_events:
        key = e.get("event_type", "UNKNOWN")
        counts[key] = counts.get(key, 0) + 1

    severities = [e.get("severity") for e in recent_events]
    critical_count = severities.count("CRITICAL")
    high_count = severities.count("HIGH")

    return f"""Analyze the overall system health based on recent activity:

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


def analyze_system_health(recent_events: list[dict]) -> dict:
    """
    Analyze overall system health using NVIDIA_API_KEY (AI Analyst section).
    Rate-limited on the same key as live events.
    """
    try:
        _rate_limit(_RATE_KEY_EVENTS)
        result = _call_nvidia(_get_client_events(), _build_health_prompt(recent_events))
        return result
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
