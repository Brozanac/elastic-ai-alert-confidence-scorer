import json
import os
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


def is_llm_configured() -> bool:
    return bool(os.getenv("OPENAI_API_KEY"))


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
    alert: dict,
    score_result: dict,
    mitre_result: dict,
    next_steps: list
) -> dict[str, Any]:
    """
    Generates an LLM-based explanation.

    Important:
    The LLM does not decide the score.
    The LLM only explains the already-calculated score.
    """

    if not is_llm_configured():
        return {
            "enabled": False,
            "error": "OPENAI_API_KEY is not configured.",
            "message": "Set OPENAI_API_KEY in your .env file to enable LLM explanations."
        }

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

    prompt = build_llm_prompt(
        alert=alert,
        score_result=score_result,
        mitre_result=mitre_result,
        next_steps=next_steps
    )

    try:
        response = client.responses.create(
            model=model,
            input=prompt
        )

        return {
            "enabled": True,
            "model": model,
            "explanation": response.output_text,
            "safety_note": "The LLM explanation is based on the existing score result. It does not calculate or override the confidence score."
        }

    except Exception as error:
        return {
            "enabled": False,
            "error": str(error),
            "message": "LLM explanation failed. The rule-based score is still valid."
        }