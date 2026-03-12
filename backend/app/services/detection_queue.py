"""
app.services.detection_queue
============================
PostgreSQL tabanlı detection queue.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from sqlalchemy import and_

from app.database.db_manager import SessionLocal, DetectionQueueModel

logger = logging.getLogger("SolidTrace.Queue")

STATUS_PENDING = "pending"
STATUS_PROCESSING = "processing"
STATUS_DONE = "done"
STATUS_DEAD = "dead"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DetectionQueueService:
    def __init__(
        self,
        worker_name: str = "worker-1",
        batch_size: int = 50,
        poll_interval: float = 1.0,
        max_attempts: int = 5,
    ):
        self.worker_name = worker_name
        self.batch_size = batch_size
        self.poll_interval = poll_interval
        self.max_attempts = max_attempts
        self._running = False

    def enqueue_many(self, tenant_id: Optional[str], payloads: list[dict[str, Any]]) -> int:
        db = SessionLocal()
        try:
            now = utcnow_iso()
            items = [
                DetectionQueueModel(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    payload_json=json.dumps(payload, ensure_ascii=False),
                    status=STATUS_PENDING,
                    created_at=now,
                    available_at=now,
                    attempts=0,
                    locked_by=None,
                    locked_at=None,
                    error_message=None,
                )
                for payload in payloads
            ]
            db.add_all(items)
            db.commit()
            return len(items)
        finally:
            db.close()

    def claim_batch(self) -> list[DetectionQueueModel]:
        db = SessionLocal()
        try:
            now = utcnow_iso()
            rows = (
                db.query(DetectionQueueModel)
                .filter(
                    and_(
                        DetectionQueueModel.status == STATUS_PENDING,
                        DetectionQueueModel.available_at <= now,
                    )
                )
                .order_by(DetectionQueueModel.created_at.asc())
                .limit(self.batch_size)
                .all()
            )

            claimed_ids = []
            for row in rows:
                row.status = STATUS_PROCESSING
                row.locked_by = self.worker_name
                row.locked_at = now
                claimed_ids.append(row.id)

            db.commit()

            if not claimed_ids:
                return []

            return db.query(DetectionQueueModel).filter(DetectionQueueModel.id.in_(claimed_ids)).all()
        finally:
            db.close()

    def mark_done(self, item_id: str) -> None:
        db = SessionLocal()
        try:
            item = db.query(DetectionQueueModel).filter(DetectionQueueModel.id == item_id).first()
            if item:
                item.status = STATUS_DONE
                item.locked_by = None
                item.locked_at = None
                item.error_message = None
                db.commit()
        finally:
            db.close()

    def mark_failed(self, item_id: str, error_message: str) -> None:
        db = SessionLocal()
        try:
            item = db.query(DetectionQueueModel).filter(DetectionQueueModel.id == item_id).first()
            if not item:
                return

            item.attempts = (item.attempts or 0) + 1
            item.error_message = (error_message or "")[:1000]
            item.locked_by = None
            item.locked_at = None

            if item.attempts >= self.max_attempts:
                item.status = STATUS_DEAD
                item.available_at = utcnow_iso()
            else:
                delay_seconds = min(60, 2 ** item.attempts)
                item.status = STATUS_PENDING
                item.available_at = (datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)).isoformat()

            db.commit()
        finally:
            db.close()

    async def run_forever(self, process_fn: Callable[[dict[str, Any], Optional[str]], Any]) -> None:
        self._running = True
        logger.info(f"🧵 Queue worker başladı: {self.worker_name}")

        while self._running:
            try:
                batch = self.claim_batch()
                if not batch:
                    await asyncio.sleep(self.poll_interval)
                    continue

                for item in batch:
                    try:
                        payload = json.loads(item.payload_json)
                        await process_fn(payload, item.tenant_id)
                        self.mark_done(item.id)
                    except Exception as exc:
                        logger.error(f"Queue item işlenemedi | id={item.id} | err={exc}")
                        self.mark_failed(item.id, str(exc))
            except Exception as exc:
                logger.error(f"Queue worker döngü hatası: {exc}")
                await asyncio.sleep(self.poll_interval)

    def stop(self) -> None:
        self._running = False