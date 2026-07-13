from ai_explainer import generate_ai_style_explanation
from context_loader import load_environment_context
from fastapi import FastAPI
from llm_explainer import generate_llm_explanation
from mitre_mapper import map_mitre
from report_generator import generate_markdown_report, generate_next_steps
from scorer import score_alert

app = FastAPI(
    title="Elastic AI Alert Confidence Scorer",
    description="Scores Elastic-style security alerts based on evidence, missing context, false-positive indicators, MITRE ATT&CK mapping, and safe AI-style explanation.",
    version="0.3.0"
)

@app.get("/environment-context")
def get_environment_context():
    return load_environment_context()

@app.get("/")
def root():
    return {
        "project": "Elastic AI Alert Confidence Scorer",
        "version": "0.3.0",
        "status": "running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "ok"
    }


@app.post("/score-alert")
def score_elastic_alert(alert: dict):
    score_result = score_alert(alert)
    mitre_result = map_mitre(alert)
    next_steps = generate_next_steps(score_result, mitre_result)

    return {
        "alert_name": score_result.get("rule_name"),
        "alert_type": score_result.get("alert_type"),
        "host": score_result.get("host"),
        "user": score_result.get("user"),
        "confidence": {
            "score": score_result.get("score"),
            "level": score_result.get("confidence")
        },
        "score_breakdown": score_result.get("score_breakdown"),
        "scoring_events": score_result.get("scoring_events"),
        "evidence": score_result.get("evidence"),
        "missing_context": score_result.get("missing_context"),
        "false_positive_notes": score_result.get("false_positive_notes"),
        "mitre_mapping": mitre_result,
        "analyst_next_steps": next_steps
    }


@app.post("/score-alert/report")
def score_elastic_alert_report(alert: dict):
    score_result = score_alert(alert)
    mitre_result = map_mitre(alert)
    markdown_report = generate_markdown_report(alert, score_result, mitre_result)

    return {
        "alert_name": score_result.get("rule_name"),
        "confidence_score": score_result.get("score"),
        "confidence_level": score_result.get("confidence"),
        "report_markdown": markdown_report
    }


@app.post("/score-alert/explain")
def explain_elastic_alert(alert: dict):
    score_result = score_alert(alert)
    mitre_result = map_mitre(alert)
    next_steps = generate_next_steps(score_result, mitre_result)

    explanation = generate_ai_style_explanation(
        alert=alert,
        score_result=score_result,
        mitre_result=mitre_result,
        next_steps=next_steps
    )

    return {
        "alert_name": score_result.get("rule_name"),
        "alert_type": score_result.get("alert_type"),
        "confidence_score": score_result.get("score"),
        "confidence_level": score_result.get("confidence"),
        "ai_style_explanation": explanation
    }


@app.post("/score-alert/full")
def full_elastic_alert_analysis(alert: dict):
    score_result = score_alert(alert)
    mitre_result = map_mitre(alert)
    next_steps = generate_next_steps(score_result, mitre_result)
    markdown_report = generate_markdown_report(alert, score_result, mitre_result)

    explanation = generate_ai_style_explanation(
        alert=alert,
        score_result=score_result,
        mitre_result=mitre_result,
        next_steps=next_steps
    )

    llm_result = generate_llm_explanation(
    alert=alert,
    score_result=score_result,
    mitre_result=mitre_result,
    next_steps=next_steps
)

    return {
        "alert_name": score_result.get("rule_name"),
        "alert_type": score_result.get("alert_type"),
        "host": score_result.get("host"),
        "user": score_result.get("user"),
        "confidence": {
            "score": score_result.get("score"),
            "level": score_result.get("confidence")
        },
        "evidence": score_result.get("evidence"),
        "missing_context": score_result.get("missing_context"),
        "false_positive_notes": score_result.get("false_positive_notes"),
        "mitre_mapping": mitre_result,
        "analyst_next_steps": next_steps,
        "ai_style_explanation": explanation,
        "llm_explanation": llm_result,
        "markdown_report": markdown_report
        
    }

@app.post("/score-alert/llm-explain")
def llm_explain_alert(alert: dict):
    score_result = score_alert(alert)
    mitre_result = map_mitre(alert)
    next_steps = generate_next_steps(score_result, mitre_result)

    llm_result = generate_llm_explanation(
        alert=alert,
        score_result=score_result,
        mitre_result=mitre_result,
        next_steps=next_steps
    )

    return {
        "alert_name": score_result.get("rule_name"),
        "alert_type": score_result.get("alert_type"),
        "host": score_result.get("host"),
        "user": score_result.get("user"),
        "confidence": {
            "score": score_result.get("score"),
            "level": score_result.get("confidence")
        },
        "score_breakdown": score_result.get("score_breakdown"),
        "scoring_events": score_result.get("scoring_events"),
        "evidence": score_result.get("evidence"),
        "missing_context": score_result.get("missing_context"),
        "false_positive_notes": score_result.get("false_positive_notes"),
        "mitre_mapping": mitre_result,
        "analyst_next_steps": next_steps,
        "llm_explanation": llm_result
    }