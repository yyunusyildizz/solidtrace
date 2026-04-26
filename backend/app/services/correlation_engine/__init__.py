"""
app.services.correlation_engine
================================
Correlation Engine package — NormalizedSecurityEvent'leri analiz edip
ilişkili olayları CorrelationGroup altında gruplar.

Public API:
    from app.services.correlation_engine import (
        CorrelationEngine,
        CorrelationGroup,
        CORRELATION_RULES,
    )
"""

from .engine import CorrelationEngine
from .models import CorrelationGroup
from .rules import CORRELATION_RULES, CorrelationRule, MatchResult

__all__ = [
    "CorrelationEngine",
    "CorrelationGroup",
    "CorrelationRule",
    "MatchResult",
    "CORRELATION_RULES",
]
