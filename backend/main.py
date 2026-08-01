import os

from ai_explainer import generate_ai_style_explanation
from app_logging import configure_logging, logger
from context_loader import load_environment_context
from database import (delete_alert_history_record, get_alert_history_record,
                      init_db, list_alert_history, save_alert_analysis)
from errors import internal_server_error, not_found
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from llm_explainer import generate_llm_explanation
from mitre_mapper import map_mitre
from report_generator import generate_markdown_report, generate_next_steps
from request_limits import RequestSizeLimitMiddleware
from schemas import AlertRequest
from scorer import score_alert

configure_logging()

def alert_to_dict(alert: AlertRequest) -> dict:
    return alert.model_dump(exclude_none=True)

app = FastAPI(
    title="Elastic AI Alert Confidence Scorer",
    description="Scores Elastic-style security alerts based on evidence, missing context, false-positive indicators, MITRE ATT&CK mapping, and safe AI-style explanation.",
    version="0.3.0"
)

MAX_REQUEST_BODY_BYTES = int(
    os.getenv("MAX_REQUEST_BODY_BYTES", "1000000")
)

app.add_middleware(
    RequestSizeLimitMiddleware,
    max_body_size=MAX_REQUEST_BODY_BYTES
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

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception(
        "unhandled_exception path=%s method=%s",
        request.url.path,
        request.method
    )

    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error. Please try again later."
        }
    )

init_db()

@app.get("/health")
def health_check():
    return {
        "status": "ok"
    }


@app.post("/score-alert")
def score_elastic_alert(alert: AlertRequest):
    alert_dict = alert_to_dict(alert)

    score_result = score_alert(alert_dict)
    mitre_result = map_mitre(alert_dict)
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
    alert_dict = alert_to_dict(alert)

    score_result = score_alert(alert_dict)
    mitre_result = map_mitre(alert_dict)
    markdown_report = generate_markdown_report(alert_dict, score_result, mitre_result)

    return {
        "alert_name": score_result.get("rule_name"),
        "confidence_score": score_result.get("score"),
        "confidence_level": score_result.get("confidence"),
        "report_markdown": markdown_report
    }


@app.post("/score-alert/explain")
def explain_elastic_alert(alert: AlertRequest):
    alert_dict = alert_to_dict(alert)

    score_result = score_alert(alert_dict)
    mitre_result = map_mitre(alert_dict)
    next_steps = generate_next_steps(score_result, mitre_result)

    explanation = generate_ai_style_explanation(
        alert=alert_dict,
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
    alert_dict = alert_to_dict(alert)

    try:
        score_result = score_alert(alert_dict)
        mitre_result = map_mitre(alert_dict)
        next_steps = generate_next_steps(score_result, mitre_result)
        markdown_report = generate_markdown_report(alert_dict, score_result, mitre_result)

        explanation = generate_ai_style_explanation(
            alert=alert_dict,
            score_result=score_result,
            mitre_result=mitre_result,
            next_steps=next_steps
        )

        llm_result = generate_llm_explanation(
            alert=alert_dict,
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
            raw_alert=alert_dict,
            analysis_result=analysis_result
        )

        analysis_result["history_id"] = saved_record.get("id")
        analysis_result["saved_to_history"] = True

        logger.info(
            "alert_analysis_completed alert_type=%s score=%s confidence=%s history_id=%s",
            score_result.get("alert_type"),
            score_result.get("score"),
            score_result.get("confidence"),
            saved_record.get("id")
        )

        return analysis_result

    except Exception:
        logger.exception("full_alert_analysis_failed")

        raise internal_server_error("Failed to retrieve alert history.")

@app.post("/score-alert/llm-explain")
def llm_explain_alert(alert: AlertRequest):
    alert_dict = alert_to_dict(alert)

    score_result = score_alert(alert_dict)
    mitre_result = map_mitre(alert_dict)
    next_steps = generate_next_steps(score_result, mitre_result)

    llm_result = generate_llm_explanation(
        alert=alert_dict,
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
def get_alert_history(limit: int = Query(default=25, ge=1, le=100)):
    try:
        items = list_alert_history(limit=limit)

        logger.info(
            "alert_history_listed limit=%s returned_count=%s",
            limit,
            len(items)
        )

        return {
            "count": len(items),
            "limit": limit,
            "items": items
        }

    except Exception:
        logger.exception("alert_history_list_failed")

        raise internal_server_error("Failed to retrieve alert history.")


@app.get("/alerts/history/{history_id}")
def get_single_alert_history_record(history_id: int):
    try:
        record = get_alert_history_record(history_id)

        if record is None:
            logger.info(
                "alert_history_record_not_found history_id=%s",
                history_id
            )

            raise not_found("Alert history record not found.")

        logger.info(
            "alert_history_record_retrieved history_id=%s",
            history_id
        )

        return record

    except HTTPException:
        raise

    except Exception:
        logger.exception(
            "alert_history_record_lookup_failed history_id=%s",
            history_id
        )

        raise internal_server_error("Failed to retrieve alert history.")


@app.delete("/alerts/history/{history_id}")
def delete_single_alert_history_record(history_id: int):
    try:
        deleted = delete_alert_history_record(history_id)

        if not deleted:
            logger.info(
                "alert_history_delete_not_found history_id=%s",
                history_id
            )

            raise not_found("Alert history record not found.")

        logger.info(
            "alert_history_record_deleted history_id=%s",
            history_id
        )

        return {
            "deleted": True,
            "history_id": history_id
        }

    except HTTPException:
        raise

    except Exception:
        logger.exception(
            "alert_history_record_delete_failed history_id=%s",
            history_id
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to delete alert history record."
        )