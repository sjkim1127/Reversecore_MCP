"""
Patch Explainer module - Backward compatibility alias.

This module was moved to common/patch_explainer.
"""

# Re-export everything from common.patch_explainer
from reversecore_mcp.tools.common.patch_explainer import *  # noqa: F403
from reversecore_mcp.tools.common.patch_explainer import (
    _generate_diff_snippet,
    _generate_explanation,
    explain_patch,
)

__all__ = [
    "explain_patch",
    "_generate_explanation",
    "_generate_diff_snippet",
]
