"""
app.core.request_logging
========================
Request logging middleware ve request context yardımcıları.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("SolidTrace.Request")


def get_client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def get_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "unknown")


def get_request_tenant_id(request: Request) -> Optional[str]:
    return getattr(request.state, "tenant_id", None)


def get_request_agent_id(request: Request) -> Optional[str]:
    return getattr(request.state, "agent_id", None)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()

        request_id = str(uuid.uuid4())
        client_ip = get_client_ip(request)
        agent_id = request.headers.get("X-Agent-Id")
        tenant_id = request.headers.get("X-Tenant-Id")

        request.state.request_id = request_id
        request.state.agent_id = agent_id
        request.state.tenant_id = tenant_id
        request.state.client_ip = client_ip

        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)

            logger.exception(
                "request_failed request_id=%s ip=%s method=%s path=%s tenant_id=%s agent_id=%s duration_ms=%s",
                request_id,
                client_ip,
                request.method,
                request.url.path,
                tenant_id,
                agent_id,
                duration_ms,
            )
            raise

        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        response.headers["X-Request-Id"] = request_id

        logger.info(
            "request_completed request_id=%s ip=%s method=%s path=%s status_code=%s tenant_id=%s agent_id=%s duration_ms=%s",
            request_id,
            client_ip,
            request.method,
            request.url.path,
            status_code,
            tenant_id,
            agent_id,
            duration_ms,
        )

        return response