import json
import sqlite3
import time
from pathlib import Path
from typing import Optional, Protocol

from app.schemas import InboundWebhookEvent, MetricsSnapshot, TriageDecision, WorkflowResponse
from app.security import detect_prompt_injection, mask_sensitive_pii


class TriageClassifier(Protocol):
    async def classify(self, clean_text: str, source: str) -> TriageDecision:
        ...


class RuleFallbackClassifier:
    """
    Deterministic classifier used when LLM_API_KEY is not configured or for local testing.
    In production, swap or wrap with OpenAI / Anthropic Structured Outputs adapter.
    """

    async def classify(self, clean_text: str, source: str) -> TriageDecision:
        low = clean_text.lower()
        if any(w in low for w in ("счет", "счёт", "оплат", "возврат", "чек", "invoice", "refund")):
            intent, queue, urgency = "billing", "crm_billing_pipeline", "high"
            reply = "Передали ваш вопрос по оплате в финансовый отдел — вернёмся с ответом в ближайшее время."
        elif any(w in low for w in ("купить", "цен", "заказ", "подключ", "тариф", "кп", "price")):
            intent, queue, urgency = "sales", "crm_sales_leads", "medium"
            reply = "Спасибо за обращение! Подготовим расчёт под вашу задачу и свяжемся с вами."
        elif any(w in low for w in ("казино", "крипто сигналы", "спам", "free money")):
            intent, queue, urgency = "spam", "archive_spam", "low"
            reply = "Обращение отклонено автоматическим фильтром."
        else:
            intent, queue = "support", "crm_support_l1"
            urgency = "high" if any(w in low for w in ("срочно", "не работает", "упал", "ошибка")) else "medium"
            reply = "Приняли обращение в техподдержку, уже проверяем детали."

        summary = clean_text[:220] + ("..." if len(clean_text) > 220 else "")
        return TriageDecision(
            intent=intent,
            urgency=urgency,
            sanitized_summary=summary,
            route_to_queue=queue,
            suggested_reply=reply,
        )


class WebhookWorkflowEngine:
    """
    Production Webhook Workflow Engine:
    - ACID Atomic idempotency via SQLite PRIMARY KEY reservation (Zero Race Conditions)
    - Sensitive PII masking before LLM dispatch
    - Multi-layered Prompt-Injection guardrails
    - Latency and SLA metrics
    """

    def __init__(self, db_path: Path, classifier: Optional[TriageClassifier] = None) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.classifier = classifier or RuleFallbackClassifier()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS webhook_events (
                    event_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    pii_masked INTEGER NOT NULL DEFAULT 0,
                    triage_json TEXT,
                    latency_ms REAL NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS counters (
                    name TEXT PRIMARY KEY,
                    val INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                "INSERT OR IGNORE INTO counters (name, val) VALUES ('duplicates_ignored', 0)"
            )

    def get_event(self, event_id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM webhook_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if not row:
                return None
            data = dict(row)
            if data.get("triage_json"):
                data["triage"] = json.loads(data.pop("triage_json"))
            return data

    async def process_event(self, event: InboundWebhookEvent) -> WorkflowResponse:
        t0 = time.perf_counter()

        # 1. Atomic Idempotency Reservation via SQLite PRIMARY KEY insert.
        # Eliminates race conditions between concurrent requests with identical event_id.
        with self._connect() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO webhook_events
                    (event_id, source, client_id, status, pii_masked, triage_json, latency_ms, created_at)
                    VALUES (?, ?, ?, 'reserved_processing', 0, NULL, 0, ?)
                    """,
                    (event.event_id, event.source, event.client_id, time.time()),
                )
            except sqlite3.IntegrityError:
                # Concurrent duplicate detected atomically at database lock level
                conn.execute(
                    "UPDATE counters SET val = val + 1 WHERE name = 'duplicates_ignored'"
                )
                existing = self.get_event(event.event_id)
                elapsed = round((time.perf_counter() - t0) * 1000, 2)
                triage_obj = (
                    TriageDecision(**existing["triage"])
                    if existing and existing.get("triage")
                    else None
                )
                return WorkflowResponse(
                    event_id=event.event_id,
                    status="duplicate_ignored",
                    triage=triage_obj,
                    pii_masked=bool(existing.get("pii_masked", False)) if existing else False,
                    latency_ms=elapsed,
                )

        # 2. Prompt-injection guardrail
        if detect_prompt_injection(event.text):
            elapsed = round((time.perf_counter() - t0) * 1000, 2)
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE webhook_events
                    SET status = 'blocked_injection', latency_ms = ?
                    WHERE event_id = ?
                    """,
                    (elapsed, event.event_id),
                )
            return WorkflowResponse(
                event_id=event.event_id,
                status="blocked_injection",
                triage=None,
                pii_masked=False,
                latency_ms=elapsed,
            )

        # 3. Mask sensitive PII before classification / external LLM dispatch
        clean_text, was_masked = mask_sensitive_pii(event.text)

        # 4. Structured AI classification
        decision = await self.classifier.classify(clean_text, event.source)
        elapsed = round((time.perf_counter() - t0) * 1000, 2)

        # 5. Finalize reserved event record atomically
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE webhook_events
                SET status = 'processed', pii_masked = ?, triage_json = ?, latency_ms = ?
                WHERE event_id = ?
                """,
                (
                    int(was_masked),
                    json.dumps(decision.model_dump()),
                    elapsed,
                    event.event_id,
                ),
            )

        return WorkflowResponse(
            event_id=event.event_id,
            status="processed",
            triage=decision,
            pii_masked=was_masked,
            latency_ms=elapsed,
        )

    def get_metrics(self) -> MetricsSnapshot:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, pii_masked, latency_ms FROM webhook_events"
            ).fetchall()
            dup_row = conn.execute(
                "SELECT val FROM counters WHERE name = 'duplicates_ignored'"
            ).fetchone()

        total = len(rows)
        duplicates = int(dup_row["val"]) if dup_row else 0
        injections = sum(1 for r in rows if r["status"] == "blocked_injection")
        processed_count = sum(1 for r in rows if r["status"] == "processed")
        latencies = [float(r["latency_ms"]) for r in rows if r["latency_ms"] > 0]
        avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

        return MetricsSnapshot(
            total_received=total + duplicates,
            processed=processed_count,
            duplicates_ignored=duplicates,
            injections_blocked=injections,
            avg_latency_ms=avg_latency,
        )
