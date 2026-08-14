import json
import os
from collections.abc import Generator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app_logging import logger
from redaction import create_redacted_copy
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

DEFAULT_DB_PATH = Path(__file__).parent / "alert_history.db"
DB_PATH = Path(os.getenv("DATABASE_PATH", str(DEFAULT_DB_PATH)))

DATABASE_URL = f"sqlite:///{DB_PATH.as_posix()}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


class AlertAnalysisHistory(Base):
    __tablename__ = "alert_analysis_history"

    id = Column(Integer, primary_key=True, index=True)
    alert_name = Column(String, nullable=False)
    alert_type = Column(String, nullable=True)
    host = Column(String, nullable=True)
    user = Column(String, nullable=True)
    score = Column(Integer, nullable=False)
    confidence = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    raw_alert_json = Column(Text, nullable=False)
    analysis_json = Column(Text, nullable=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()

def save_alert_analysis(
    db: Session,
    raw_alert: dict,
    analysis_result: dict
) -> dict:
    try:
        safe_raw_alert = create_redacted_copy(raw_alert)
        safe_analysis_result = create_redacted_copy(analysis_result)

        record = AlertAnalysisHistory(
            alert_name=safe_analysis_result.get("alert_name", "Unknown Alert"),
            alert_type=safe_analysis_result.get("alert_type", "unknown"),
            host=safe_analysis_result.get("host", "unknown"),
            user=safe_analysis_result.get("user", "unknown"),
            score=safe_analysis_result.get("confidence", {}).get("score", 0),
            confidence=safe_analysis_result.get("confidence", {}).get(
                "level",
                "Unknown"
            ),
            raw_alert_json=json.dumps(safe_raw_alert),
            analysis_json=json.dumps(safe_analysis_result),
        )

        db.add(record)
        db.commit()
        db.refresh(record)

        logger.info(
            "database_alert_analysis_saved history_id=%s alert_type=%s score=%s",
            record.id,
            record.alert_type,
            record.score
        )

        return serialize_history_record(record, include_full_analysis=False)

    except Exception:
        db.rollback()

        logger.exception(
            "database_save_alert_analysis_failed alert_name=%s alert_type=%s",
            analysis_result.get("alert_name", "unknown"),
            analysis_result.get("alert_type", "unknown")
        )

        raise


def list_alert_history(db: Session, limit: int = 25) -> list[dict[str, Any]]:
    try:
        records = (
            db.query(AlertAnalysisHistory)
            .order_by(AlertAnalysisHistory.created_at.desc())
            .limit(limit)
            .all()
        )

        logger.info(
            "database_alert_history_listed limit=%s returned_count=%s",
            limit,
            len(records)
        )

        return [
            serialize_history_record(record, include_full_analysis=False)
            for record in records
        ]

    except Exception:
        logger.exception(
            "database_list_alert_history_failed limit=%s",
            limit
        )

        raise


def get_alert_history_record(
    db: Session,
    history_id: int
) -> dict[str, Any] | None:
    try:
        record = (
            db.query(AlertAnalysisHistory)
            .filter(AlertAnalysisHistory.id == history_id)
            .first()
        )

        if record is None:
            return None

        return serialize_history_record(record, include_full_analysis=True)

    except Exception:
        logger.exception(
            "database_get_alert_history_record_failed history_id=%s",
            history_id
        )
        raise


def delete_alert_history_record(db: Session, history_id: int) -> bool:
    try:
        record = (
            db.query(AlertAnalysisHistory)
            .filter(AlertAnalysisHistory.id == history_id)
            .first()
        )

        if record is None:
            logger.info(
                "database_alert_history_delete_not_found history_id=%s",
                history_id
            )
            return False

        db.delete(record)
        db.commit()

        logger.info(
            "database_alert_history_record_deleted history_id=%s",
            history_id
        )

        return True

    except Exception:
        db.rollback()

        logger.exception(
            "database_delete_alert_history_record_failed history_id=%s",
            history_id
        )

        raise

def safe_json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback

    try:
        return json.loads(value)
    except json.JSONDecodeError:
        logger.exception("history_record_json_decode_failed")
        return fallback


def serialize_history_record(
    record: AlertAnalysisHistory,
    include_full_analysis: bool
) -> dict[str, Any]:
    created_at = None

    if record.created_at is not None:
        created_at = record.created_at.isoformat()

    result = {
        "id": record.id,
        "alert_name": record.alert_name,
        "alert_type": record.alert_type,
        "host": record.host,
        "user": record.user,
        "score": record.score,
        "confidence": record.confidence,
        "created_at": created_at,
    }

    if include_full_analysis:
        result["raw_alert"] = safe_json_loads(
            record.raw_alert_json,
            fallback={}
        )
        result["analysis"] = safe_json_loads(
            record.analysis_json,
            fallback={}
        )

    return result