from __future__ import annotations

import json

from apisentinel.database.models import ScanRecord
from apisentinel.database.session import SessionLocal, init_db
from apisentinel.scanner.models import ScanResult


class ScanRepository:
    def __init__(self) -> None:
        init_db()

    def save(self, result: ScanResult) -> ScanRecord:
        payload = result.model_dump(mode="json")
        record = ScanRecord(
            id=result.id,
            target=result.target,
            score=result.summary.score,
            findings_count=result.summary.findings_count,
            result_json=json.dumps(payload),
        )
        with SessionLocal() as session:
            session.merge(record)
            session.commit()
            session.refresh(record)
            return record

    def list(self, limit: int = 50) -> list[ScanResult]:
        with SessionLocal() as session:
            records = session.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit).all()
            return [ScanResult.model_validate_json(record.result_json) for record in records]

    def get(self, scan_id: str) -> ScanResult | None:
        with SessionLocal() as session:
            record = session.get(ScanRecord, scan_id)
            if not record:
                return None
            return ScanResult.model_validate_json(record.result_json)
