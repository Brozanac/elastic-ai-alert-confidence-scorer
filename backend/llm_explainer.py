import json
import os
from typing import Any

from app_logging import logger
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


def is_llm_configured() -> bool:
    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        return False

    placeholder_values = {
        "your_openai_api_key_here",
        "your_api_key_here",
        "change_me",
        "changeme",
        "your_real_key_here",
    }

    if api_key.strip().lower() in placeholder_values:
        return False

    return True

def build_llm_prompt(
    alert: dict,
    score_result: dict,
    mitre_result: dict,
    next_steps: list
) -> str:
    return f"""
You are a SOC analyst assistant helping explain an alert confidence score.

Your job:
Explain the existing confidence score in clear analyst language.

Strict rules:
- Do not change the confidence score.
- Do not create a new score.
- Do not invent facts.
- Do not claim the alert is confirmed malicious.
- Only use the supplied alert, evidence, score breakdown, MITRE mapping, and next steps.
- Clearly separate confirmed evidence from missing context.
- Mention false-positive context if present.
- Keep the explanation concise and practical.
- Use a professional SOC analyst tone.

Return your answer with these sections:

1. Executive Summary
2. Why the Score Was Assigned
3. Key Evidence
4. Missing Context
5. False-Positive Considerations
6. Recommended Analyst Actions

Alert JSON:
{json.dumps(alert, indent=2)}

Score Result:
{json.dumps(score_result, indent=2)}

MITRE Mapping:
{json.dumps(mitre_result, indent=2)}

Analyst Next Steps:
{json.dumps(next_steps, indent=2)}
"""


def generate_llm_explanation(
    alert: dict[str, Any],
    score_result: dict[str, Any],
    mitre_result: dict[str, Any],
    next_steps: list[str],
) -> dict[str, Any]:
    if not is_llm_configured():
        logger.info("llm_explanation_skipped reason=api_key_not_configured")

        return {
            "enabled": False,
            "error": "OPENAI_API_KEY is not configured.",
            "message": "LLM explanation is disabled. The rule-based score is still valid."
        }

    try:
        model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
        client = OpenAI()

        prompt = build_llm_prompt(
            alert=alert,
            score_result=score_result,
            mitre_result=mitre_result,
            next_steps=next_steps
        )

        response = client.responses.create(
            model=model,
            input=prompt
        )

        logger.info(
            "llm_explanation_completed model=%s alert_type=%s score=%s",
            model,
            score_result.get("alert_type", "unknown"),
            score_result.get("score", "unknown")
        )

        return {
            "enabled": True,
            "model": model,
            "explanation": response.output_text,
            "safety_note": (
                "The LLM explanation summarizes the existing deterministic score. "
                "It does not create or modify the confidence score."
            )
        }

    except Exception:
        logger.exception(
            "llm_explanation_failed alert_type=%s score=%s",
            score_result.get("alert_type", "unknown"),
            score_result.get("score", "unknown")
        )

        return {
            "enabled": False,
            "error": "LLM explanation failed.",
            "message": "The rule-based score is still valid."
        }