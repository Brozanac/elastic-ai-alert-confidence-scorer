import os

from ai_explainer import generate_ai_style_explanation
from app_logging import configure_logging, logger
from auth import require_api_key
from context_loader import load_environment_context
from database import (delete_alert_history_record, get_alert_history_record,
                      get_db, init_db, list_alert_history, save_alert_analysis)
from dotenv import load_dotenv
from elastic_normalizer import normalize_elastic_alert_for_scoring
from errors import internal_server_error, not_found
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from llm_explainer import generate_llm_explanation
from mitre_mapper import map_mitre
from report_generator import generate_markdown_report, generate_next_steps
from request_limits import RequestSizeLimitMiddleware
from schemas import AlertRequest
from scorer import score_alert
from sqlalchemy.orm import Session

configure_logging()
load_dotenv()

def alert_to_dict(alert: AlertRequest) -> dict:
    return alert.model_dump(exclude_none=True, by_alias=True,)

app = FastAPI(
    title="Elastic AI Alert Confidence Scorer",
    description="Scores Elastic-style security alerts based on evidence, missing context, false-positive indicators, MITRE ATT&CK mapping, and safe AI-style explanation.",
    version="0.3.0"
)

@app.middleware("http")
async def log_requests_safely(request: Request, call_next):
    logger.info(
        "request_started method=%s path=%s",
        request.method,
        request.url.path
    )

    response = await call_next(request)

    logger.info(
        "request_completed method=%s path=%s status_code=%s",
        request.method,
        request.url.path,
        response.status_code
    )

    return response

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    return response

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

def get_allowed_origins() -> list[str]:
    raw_origins = os.getenv(
        "ALLOWED_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173"
    )

    return [
        origin.strip()
        for origin in raw_origins.split(",")
        if origin.strip()
    ]



app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
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
    raw_alert_dict = alert_to_dict(alert)
    alert_dict = normalize_elastic_alert_for_scoring(raw_alert_dict)

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
    raw_alert_dict = alert_to_dict(alert)
    alert_dict = normalize_elastic_alert_for_scoring(raw_alert_dict)

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
    raw_alert_dict = alert_to_dict(alert)
    alert_dict = normalize_elastic_alert_for_scoring(raw_alert_dict)

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
def full_elastic_alert_analysis(alert: AlertRequest, db: Session = Depends(get_db)):
    raw_alert_dict = alert_to_dict(alert)
    alert_dict = normalize_elastic_alert_for_scoring(raw_alert_dict)

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
    "markdown_report": markdown_report,
    "elastic_context": {
        "timestamp": alert_dict.get("elastic", {}).get("timestamp"),
        "ecs_version": alert_dict.get("elastic", {}).get("ecs_version"),
        "event_id": alert_dict.get("elastic", {}).get("event_id"),
        "event_dataset": alert_dict.get("elastic", {}).get("event_dataset"),
        "event_module": alert_dict.get("elastic", {}).get("event_module"),
        "event_kind": alert_dict.get("event", {}).get("kind"),
        "event_category": alert_dict.get("event", {}).get("category"),
        "event_type": alert_dict.get("event", {}).get("type"),
    }
}

        saved_record = save_alert_analysis(
    db=db,
    raw_alert=raw_alert_dict,
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

        raise internal_server_error("Alert analysis failed. Please try again.")

@app.post("/score-alert/llm-explain")
def llm_explain_alert(alert: AlertRequest):
    raw_alert_dict = alert_to_dict(alert)
    alert_dict = normalize_elastic_alert_for_scoring(raw_alert_dict)

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


@app.get("/alerts/history", dependencies=[Depends(require_api_key)])
def get_alert_history(
    limit: int = Query(default=25, ge=1, le=100),
    db: Session = Depends(get_db)
):
    try:
        items = list_alert_history(db=db, limit=limit)

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

        raise internal_server_error(
            "Failed to retrieve alert history."
        )


@app.get("/alerts/history/{history_id}", dependencies=[Depends(require_api_key)])
def get_single_alert_history_record(
    history_id: int,
    db: Session = Depends(get_db)
):
    try:
        record = get_alert_history_record(
            db=db,
            history_id=history_id
        )

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

        raise internal_server_error(
            "Failed to retrieve alert history record."
        )


@app.delete("/alerts/history/{history_id}", dependencies=[Depends(require_api_key)])
def delete_single_alert_history_record(
    history_id: int,
    db: Session = Depends(get_db)
):
    try:
        deleted = delete_alert_history_record(
            db=db,
            history_id=history_id
        )

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

        raise internal_server_error(
            "Failed to delete alert history record."
        )