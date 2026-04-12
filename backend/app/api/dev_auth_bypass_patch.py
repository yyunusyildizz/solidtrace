from __future__ import annotations

import os
from typing import Optional

from fastapi import Header, HTTPException, Request

from app.core.security import verify_agent_request


async def resolve_agent_tenant_id(
    request: Request,
    x_agent_id: Optional[str] = Header(default=None, alias="X-Agent-Id"),
) -> str:
    # Env'yi import time'da değil, request time'da oku
    dev_bypass_agent_auth = os.getenv("DEV_BYPASS_AGENT_AUTH", "false").lower() == "true"
    dev_bypass_tenant_id = os.getenv("DEV_BYPASS_TENANT_ID", "default_tenant")
    dev_bypass_agent_id = os.getenv("DEV_BYPASS_AGENT_ID", "DESKTOP-UI41CTM")

    if dev_bypass_agent_auth:
        if x_agent_id and x_agent_id != dev_bypass_agent_id:
            raise HTTPException(
                status_code=403,
                detail=f"Dev bypass aktif ama X-Agent-Id beklenen değerle eşleşmiyor: {dev_bypass_agent_id}",
            )
        return dev_bypass_tenant_id

    maybe_result = verify_agent_request(request)

    if hasattr(maybe_result, "__await__"):
        return await maybe_result

    return maybe_result