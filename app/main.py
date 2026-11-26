import os
import warnings
from pathlib import Path
from fastapi import Depends, FastAPI, Header, HTTPException, Request

from app.schemas import InboundWebhookEvent, MetricsSnapshot, WorkflowResponse
from app.security import SlidingWindowRateLimiter, verify_hmac_signature
from app.workflow import WebhookWorkflowEngine


def create_app(
    db_path: Path | None = None,
    api_key: str | None = None,
    webhook_secret: str | None = None,
    rate_limit_per_min: int = 30,
    redis_client: object | None = None,
) -> FastAPI:
    app = FastAPI(
        title="AI Webhook Workflow Starter",
        description=(
            "Production-ready FastAPI template for inbound CRM / Telegram AI workflows: "
            "atomic ACID idempotency, PII masking, prompt-injection guardrails, HMAC verification, "
            "sliding-window rate limiting, and metrics."
        ),
        version="1.1.0",
    )

    env = os.getenv("ENV", os.getenv("ENVIRONMENT", "development")).lower()
    raw_key = api_key if api_key is not None else os.getenv("WEBHOOK_API_KEY")
    if not raw_key:
        if env in ("production", "prod", "stage", "staging"):
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: WEBHOOK_API_KEY environment variable is "
                "strictly required in production mode. Refusing to boot with default secrets."
            )
        raw_key = "dev-webhook-key"
        warnings.warn(
            "WEBHOOK_API_KEY not configured. Running with insecure fallback 'dev-webhook-key' in development mode.",
            UserWarning,
            stacklevel=2,
        )

    expected_key = raw_key
    expected_secret = (
        webhook_secret if webhook_secret is not None else os.getenv("WEBHOOK_SECRET")
    )

    resolved_db = db_path or Path(os.getenv("WORKFLOW_DB_PATH", "./data/events.db"))
    engine = WebhookWorkflowEngine(resolved_db)
    limiter = SlidingWindowRateLimiter(
        max_requests=rate_limit_per_min, window_seconds=60, redis_client=redis_client
    )

    async def verify_auth_and_hmac(
        request: Request,
        x_api_key: str | None = Header(default=None),
        x_hub_signature_256: str | None = Header(default=None),
        x_signature: str | None = Header(default=None),
    ) -> None:
        # 1. API-Key Header verification
        api_key_valid = bool(x_api_key and x_api_key == expected_key)

        # 2. HMAC-SHA256 signature verification (when secret and signature header are provided)
        sig_header = x_hub_signature_256 or x_signature
        hmac_valid = False
        if expected_secret and sig_header:
            body = await request.body()
            hmac_valid = verify_hmac_signature(body, sig_header, expected_secret)

        if not api_key_valid and not hmac_valid:
            raise HTTPException(
                status_code=401,
                detail="Unauthorized: Valid X-API-Key or valid HMAC signature (X-Hub-Signature-256) is required",
            )

    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "service": "ai-webhook-workflow-starter",
            "environment": env,
            "atomic_idempotency": True,
            "hmac_supported": bool(expected_secret),
        }

    @app.post(
        "/v1/webhooks/inbound",
        response_model=WorkflowResponse,
        dependencies=[Depends(verify_auth_and_hmac)],
    )
    async def inbound_webhook(event: InboundWebhookEvent):
        if not limiter.allow(event.client_id):
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded for client_id",
            )
        return await engine.process_event(event)

    @app.get("/v1/events/{event_id}", dependencies=[Depends(verify_auth_and_hmac)])
    async def get_event_audit(event_id: str):
        record = engine.get_event(event_id)
        if not record:
            raise HTTPException(status_code=404, detail="Event not found")
        return record

    @app.get(
        "/v1/metrics",
        response_model=MetricsSnapshot,
        dependencies=[Depends(verify_auth_and_hmac)],
    )
    async def metrics():
        return engine.get_metrics()

    return app


app = create_app()
