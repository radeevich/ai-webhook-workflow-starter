import hashlib
import hmac
import os
import re
import threading
import time
import unicodedata
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple

# Advanced Prompt-Injection heuristics: system prompt leaks, instruction resets, role hijacking, and delimiter attacks
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"(reveal|print|show|output)\s+(your\s+)?(system\s+prompt|api\s*key|secret|rules)", re.IGNORECASE),
    re.compile(r"забудь\s+(все\s+)?(предыдущие\s+)?инструкции", re.IGNORECASE),
    re.compile(r"(покажи|выведи|раскрой)\s+(системный\s+промпт|ключи|пароли|токен)", re.IGNORECASE),
    re.compile(r"(jailbreak|dan\s+mode|developer\s+mode|unfiltered\s+mode)", re.IGNORECASE),
    re.compile(r"(<\|im_start\|>|<\|system\|>|\[INST\]|```system)", re.IGNORECASE),
    re.compile(r"you\s+are\s+no\s+longer\s+bound\s+by", re.IGNORECASE),
]

CARD_RE = re.compile(r"\b(?:\d[ -]*?){16}\b")
SECRET_TOKEN_RE = re.compile(r"\b((?:sk|ghp|gho|vcp|bot)[-_a-zA-Z0-9]{16,})\b")


def normalize_text(text: str) -> str:
    """Strips zero-width characters and normalizes unicode to defeat evasion attacks."""
    cleaned = re.sub(r"[\u200B-\u200D\uFEFF]", "", text)
    return unicodedata.normalize("NFKC", cleaned)


def detect_prompt_injection(text: str) -> bool:
    norm = normalize_text(text)
    for pattern in INJECTION_PATTERNS:
        if pattern.search(norm):
            return True
    return False


def mask_sensitive_pii(text: str) -> Tuple[str, bool]:
    """Masks payment card numbers and leaked API tokens before sending text to external LLMs."""
    masked = CARD_RE.sub("[CARD_MASKED]", text)
    masked = SECRET_TOKEN_RE.sub("[SECRET_MASKED]", masked)
    return masked, (masked != text)


def verify_hmac_signature(raw_body: bytes, signature_header: str, secret: str) -> bool:
    """Verifies HMAC-SHA256 signature against request body with constant-time comparison."""
    if not signature_header or not secret:
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    provided = signature_header.removeprefix("sha256=").strip()
    return hmac.compare_digest(expected, provided)


class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter with:
    - Thread-safe locked in-memory sliding window for single-worker/local mode
    - Optional Redis distributed backend when redis_client / REDIS_URL is configured
    """

    def __init__(
        self,
        max_requests: int = 30,
        window_seconds: int = 60,
        redis_client: Optional[object] = None,
    ) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.redis = redis_client
        self._lock = threading.Lock()
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, client_id: str) -> bool:
        # 1. Distributed Redis sliding window when Redis is provided
        if self.redis is not None:
            try:
                now = time.time()
                key = f"rl:{client_id}"
                pipeline = self.redis.pipeline()
                pipeline.zremrangebyscore(key, 0, now - self.window_seconds)
                pipeline.zadd(key, {str(now): now})
                pipeline.zcard(key)
                pipeline.expire(key, self.window_seconds + 5)
                _, _, count, _ = pipeline.execute()
                return count <= self.max_requests
            except Exception:
                # Fall back to local memory if Redis experiences transient connectivity error
                pass

        # 2. Thread-safe in-memory sliding window
        with self._lock:
            now = time.monotonic()
            q = self._hits[client_id]
            cutoff = now - self.window_seconds
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self.max_requests:
                return False
            q.append(now)
            return True
