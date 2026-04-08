from __future__ import annotations

import asyncio
import math
import time
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from hmac import compare_digest
from ipaddress import ip_address
from typing import Deque

from fastapi import HTTPException, Request, Response

from app.config import settings

ADMIN_TOKEN_HEADER = "X-FlameGuard-Admin-Token"
FRONT_DOOR_CLIENT_IP_HEADER = "X-Azure-ClientIP"
FRONT_DOOR_ORIGIN_TOKEN_HEADER = "X-FlameGuard-Origin-Token"
RATE_LIMIT_HEADER_LIMIT = "X-RateLimit-Limit"
RATE_LIMIT_HEADER_REMAINING = "X-RateLimit-Remaining"
RATE_LIMIT_HEADER_RESET = "X-RateLimit-Reset"

_UPLOAD_HEADER_OVERHEAD_BYTES = 1024 * 1024


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    reset_after_seconds: int
    retry_after_seconds: int | None = None


class SlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], Deque[float]] = {}
        self._lock = asyncio.Lock()

    async def check(
        self,
        *,
        bucket: str,
        client_id: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitResult:
        now = time.monotonic()
        key = (bucket, client_id)

        async with self._lock:
            hits = self._hits.setdefault(key, deque())
            cutoff = now - window_seconds
            while hits and hits[0] <= cutoff:
                hits.popleft()

            if len(hits) >= limit:
                retry_after = max(1, math.ceil(window_seconds - (now - hits[0])))
                return RateLimitResult(
                    allowed=False,
                    limit=limit,
                    remaining=0,
                    reset_after_seconds=retry_after,
                    retry_after_seconds=retry_after,
                )

            hits.append(now)
            reset_after = max(1, math.ceil(window_seconds - (now - hits[0])))
            return RateLimitResult(
                allowed=True,
                limit=limit,
                remaining=max(limit - len(hits), 0),
                reset_after_seconds=reset_after,
            )

    async def reset(self) -> None:
        async with self._lock:
            self._hits.clear()


_rate_limiter = SlidingWindowRateLimiter()
_audit_job_semaphore: asyncio.Semaphore | None = None
_audit_job_semaphore_limit: int | None = None


def _forwarded_client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_ip = forwarded_for.split(",", 1)[0].strip()
        if client_ip:
            return client_ip

    forwarded = request.headers.get("forwarded")
    if forwarded:
        for part in forwarded.split(";"):
            token = part.strip()
            if token.lower().startswith("for="):
                client_ip = token[4:].strip().strip('"').strip("[]")
                if client_ip:
                    return client_ip

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        client_ip = real_ip.strip()
        if client_ip:
            return client_ip

    return None


def _should_trust_proxy_headers(request: Request) -> bool:
    if not settings.trust_proxy_headers:
        return False

    configured_origin_token = settings.front_door_origin_token.strip()
    if configured_origin_token:
        provided_origin_token = request.headers.get(FRONT_DOOR_ORIGIN_TOKEN_HEADER, "")
        return bool(provided_origin_token) and compare_digest(provided_origin_token, configured_origin_token)

    if not request.client or not request.client.host:
        return False

    try:
        client_ip = ip_address(request.client.host)
    except ValueError:
        return False

    return any(client_ip in network for network in settings.parsed_trusted_proxy_networks)


def get_client_address(request: Request) -> str:
    if _should_trust_proxy_headers(request):
        front_door_client_ip = request.headers.get(FRONT_DOOR_CLIENT_IP_HEADER, "").strip()
        if front_door_client_ip:
            return front_door_client_ip

        forwarded_ip = _forwarded_client_ip(request)
        if forwarded_ip:
            return forwarded_ip

    if request.client and request.client.host:
        return request.client.host

    return "unknown"


def _rate_limit_headers(result: RateLimitResult) -> dict[str, str]:
    headers = {
        RATE_LIMIT_HEADER_LIMIT: str(result.limit),
        RATE_LIMIT_HEADER_REMAINING: str(result.remaining),
        RATE_LIMIT_HEADER_RESET: str(result.reset_after_seconds),
    }
    if result.retry_after_seconds is not None:
        headers["Retry-After"] = str(result.retry_after_seconds)
    return headers


def rate_limit_dependency(
    bucket: str,
    label: str,
    limit_setting: str,
    window_setting: str,
):
    async def dependency(request: Request, response: Response) -> None:
        if not settings.rate_limit_enabled:
            return

        limit = max(0, int(getattr(settings, limit_setting, 0)))
        window_seconds = max(0, int(getattr(settings, window_setting, 0)))
        if limit == 0 or window_seconds == 0:
            return

        result = await _rate_limiter.check(
            bucket=bucket,
            client_id=get_client_address(request),
            limit=limit,
            window_seconds=window_seconds,
        )
        headers = _rate_limit_headers(result)
        for name, value in headers.items():
            response.headers[name] = value

        if not result.allowed:
            raise HTTPException(
                status_code=429,
                detail=f"Too many {label} from this client. Retry in {result.retry_after_seconds} seconds.",
                headers=headers,
            )

    return dependency


async def enforce_upload_content_length(request: Request) -> None:
    content_length = request.headers.get("content-length")
    if not content_length:
        return

    try:
        declared_size = int(content_length)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid Content-Length header") from exc

    max_allowed = settings.upload_max_size_mb * 1024 * 1024 + _UPLOAD_HEADER_OVERHEAD_BYTES
    if declared_size > max_allowed:
        raise HTTPException(
            status_code=413,
            detail=f"Upload exceeds the {settings.upload_max_size_mb}MB limit.",
        )


def require_admin_token(request: Request) -> None:
    configured_token = settings.admin_api_token.strip()
    if not configured_token:
        raise HTTPException(
            status_code=403,
            detail="Administrative routes are disabled on this deployment.",
        )

    provided_token = request.headers.get(ADMIN_TOKEN_HEADER, "")
    if not provided_token or not compare_digest(provided_token, configured_token):
        raise HTTPException(
            status_code=403,
            detail="Administrative token required for this route.",
        )


def apply_api_security_headers(request: Request, response: Response) -> None:
    if not request.url.path.startswith("/api/"):
        return

    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Pragma", "no-cache")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy",
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
    )


upload_rate_limit = rate_limit_dependency(
    bucket="upload",
    label="upload requests",
    limit_setting="upload_rate_limit_requests",
    window_setting="upload_rate_limit_window_seconds",
)

generation_rate_limit = rate_limit_dependency(
    bucket="generation",
    label="AI generation requests",
    limit_setting="generation_rate_limit_requests",
    window_setting="generation_rate_limit_window_seconds",
)

chat_rate_limit = rate_limit_dependency(
    bucket="chat",
    label="chat requests",
    limit_setting="chat_rate_limit_requests",
    window_setting="chat_rate_limit_window_seconds",
)

read_rate_limit = rate_limit_dependency(
    bucket="read",
    label="read requests",
    limit_setting="read_rate_limit_requests",
    window_setting="read_rate_limit_window_seconds",
)

admin_mutation_rate_limit = rate_limit_dependency(
    bucket="admin-mutation",
    label="administrative write requests",
    limit_setting="admin_mutation_rate_limit_requests",
    window_setting="admin_mutation_rate_limit_window_seconds",
)


def _get_audit_job_semaphore() -> asyncio.Semaphore:
    global _audit_job_semaphore, _audit_job_semaphore_limit

    limit = max(1, settings.max_concurrent_audit_jobs)
    if _audit_job_semaphore is None or _audit_job_semaphore_limit != limit:
        _audit_job_semaphore = asyncio.Semaphore(limit)
        _audit_job_semaphore_limit = limit

    return _audit_job_semaphore


@asynccontextmanager
async def acquire_audit_job_slot():
    semaphore = _get_audit_job_semaphore()
    await semaphore.acquire()
    try:
        yield
    finally:
        semaphore.release()


def reset_security_state() -> None:
    global _audit_job_semaphore, _audit_job_semaphore_limit

    _rate_limiter._hits.clear()
    _audit_job_semaphore = None
    _audit_job_semaphore_limit = None