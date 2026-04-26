"""
app.services.story_pipeline
==============================
Story Pipeline package — raw event / alert / command result'ları
NormalizedSecurityEvent → CorrelationGroup → AttackStory pipeline'ından geçirir.

Public API:
    from app.services.story_pipeline import StoryPipeline, StoryPipelineResult
"""

from .pipeline import StoryPipeline, StoryPipelineResult

__all__ = [
    "StoryPipeline",
    "StoryPipelineResult",
]
