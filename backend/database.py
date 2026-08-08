import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app_logging import logger
from redaction import create_redacted_copy
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = Path(__file__).parent / "alert_history.db"
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


def save_alert_analysis(raw_alert: dict, analysis_result: dict) -> dict:
    session = SessionLocal()

    try:
        safe_raw_alert = create_redacted_copy(raw_alert)
        safe_analysis_result = create_redacted_copy(analysis_result)

        record = AlertAnalysisHistory(
            alert_name=safe_analysis_result.get("alert_name", "Unknown Alert"),
            alert_type=safe_analysis_result.get("alert_type", "unknown"),
            host=safe_analysis_result.get("host", "unknown"),
            user=safe_analysis_result.get("user", "unknown"),
            score=safe_analysis_result.get("confidence", {}).get("score", 0),
            confidence=safe_analysis_result.get("confidence", {}).get("level", "Unknown"),
            raw_alert_json=json.dumps(safe_raw_alert),
            analysis_json=json.dumps(safe_analysis_result),
        )

        session.add(record)
        session.commit()
        session.refresh(record)

        return serialize_history_record(record, include_full_analysis=False)

    except Exception:
        session.rollback()
        logger.exception("database_save_alert_analysis_failed")
        raise

    finally:
        session.close()


def list_alert_history(limit: int = 25) -> list[dict[str, Any]]:
    session = SessionLocal()

    try:
        records = (
            session.query(AlertAnalysisHistory)
            .order_by(AlertAnalysisHistory.created_at.desc())
            .limit(limit)
            .all()
        )

        return [
            serialize_history_record(record, include_full_analysis=False)
            for record in records
        ]

    except Exception:
        logger.exception("database_list_alert_history_failed")
        raise

    finally:
        session.close()


def get_alert_history_record(history_id: int) -> dict[str, Any] | None:
    session = SessionLocal()

    try:
        record = (
            session.query(AlertAnalysisHistory)
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

    finally:
        session.close()


def delete_alert_history_record(history_id: int) -> bool:
    session = SessionLocal()

    try:
        record = (
            session.query(AlertAnalysisHistory)
            .filter(AlertAnalysisHistory.id == history_id)
            .first()
        )

        if record is None:
            return False

        session.delete(record)
        session.commit()

        return True

    except Exception:
        session.rollback()

        logger.exception(
            "database_delete_alert_history_record_failed history_id=%s",
            history_id
        )
        raise

    finally:
        session.close()


def serialize_history_record(
    record: AlertAnalysisHistory,
    include_full_analysis: bool
) -> dict[str, Any]:
    result = {
        "id": record.id,
        "alert_name": record.alert_name,
        "alert_type": record.alert_type,
        "host": record.host,
        "user": record.user,
        "score": record.score,
        "confidence": record.confidence,
        "created_at": record.created_at.isoformat()
    }

    if include_full_analysis:
        result["raw_alert"] = json.loads(record.raw_alert_json)
        result["analysis"] = json.loads(record.analysis_json)

    return result