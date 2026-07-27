from ai_explainer import generate_ai_style_explanation
from context_loader import load_environment_context
from database import (delete_alert_history_record, get_alert_history_record,
                      init_db, list_alert_history, save_alert_analysis)
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from llm_explainer import generate_llm_explanation
from mitre_mapper import map_mitre
from report_generator import generate_markdown_report, generate_next_steps
from schemas import AlertRequest
from scorer import score_alert


def alert_to_dict(alert: AlertRequest) -> dict:
    return alert.model_dump(exclude_none=True)

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

@app.get("/health")
def health_check():
    return {
        "status": "ok"
    }


@app.post("/score-alert")
def score_elastic_alert(alert: AlertRequest):
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
def score_elastic_alert_report(alert: AlertRequest):
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
def explain_elastic_alert(alert: AlertRequest):
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
def full_elastic_alert_analysis(alert: AlertRequest):
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

    analysis_result = {
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
        "ai_style_explanation": explanation,
        "llm_explanation": llm_result,
        "markdown_report": markdown_report
    }

    saved_record = save_alert_analysis(
        raw_alert=alert,
        analysis_result=analysis_result
    )

    analysis_result["history_id"] = saved_record.get("id")
    analysis_result["saved_to_history"] = True

    return analysis_result

@app.post("/score-alert/llm-explain")
def llm_explain_alert(alert: AlertRequest):
    alert_dict = alert_to_dict(alert)
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


@app.get("/alerts/history")
def get_alert_history(limit: int = 25):
    return {
        "count": limit,
        "items": list_alert_history(limit=limit)
    }


@app.get("/alerts/history/{history_id}")
def get_single_alert_history_record(history_id: int):
    record = get_alert_history_record(history_id)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Alert history record not found"
        )

    return record


@app.delete("/alerts/history/{history_id}")
def delete_single_alert_history_record(history_id: int):
    deleted = delete_alert_history_record(history_id)

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Alert history record not found"
        )

    return {
        "deleted": True,
        "history_id": history_id
    }