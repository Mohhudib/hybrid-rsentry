"""
ai_analyst.py — NVIDIA AI analysis for suspicious events.
Uses nvidia/llama-3.1-nemotron-70b-instruct via OpenAI-compatible API.
Classifies threats, detects techniques/languages, explains behavior.
"""
import json
import logging
import os
import re

from openai import OpenAI

logger = logging.getLogger(__name__)

MODEL_NAME = "nvidia/llama-3.1-nemotron-70b-instruct"

_client = None


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
    if ancestors:
        lines.append(f"Process ancestors: {' → '.join(str(a) for a in ancestors[:5])}")
    if reasons:
        lines.append(f"Lineage reasons: {', '.join(str(r) for r in reasons[:5])}")
    if details.get("combined_score"):
        lines.append(f"Combined threat score: {details['combined_score']}")

    return "Analyze this detection event:\n\n" + "\n".join(lines)


def analyze_event(event: dict) -> dict:
    """
    Call NVIDIA Nemotron to analyze a detection event.
    Returns a dict with threat classification and recommendations.
    Returns a fallback dict if the API call fails.
    """
    try:
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

        # Extract JSON from response
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
        return json.loads(text)

    except Exception as exc:
        logger.warning("NVIDIA AI analysis failed: %s", exc)
        return {
            "threat_type": "Analysis unavailable",
            "technique": "—",
            "language_or_tool": "—",
            "behavior_summary": f"AI analysis could not be completed: {str(exc)[:80]}",
            "risk_level": event.get("severity", "UNKNOWN"),
            "recommendation": "Review event manually.",
            "confidence": "LOW",
        }


def analyze_system_health(recent_events: list[dict]) -> dict:
    """
    Analyze overall system behavior stability from recent events.
    Returns health assessment.
    """
    try:
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
