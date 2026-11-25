"""Patch Generator Agent (M3B). Produces UNVERIFIED candidate patches only.

``PatchGeneratorAgent.generate`` returns a ``PatchGeneration``:
``.candidate`` is report-safe; ``.patched_source`` is execution-only and
refuses serialization.
"""

from .agent import PatchGeneratorAgent
from .context import PatchContext, build_patch_context
from .diff import ParsedDiff, apply_diff, parse_unified_diff
from .errors import (
    ContextTooLargeError,
    DiffApplyError,
    DiffFormatError,
    DiffHunkError,
    DiffPathError,
    DiffScopeError,
    EmptyDiffError,
    InsufficientContextError,
    InvalidDiffError,
    InvalidFindingError,
    MalformedPatchResponseError,
    MultiFileDiffError,
    NoOpDiffError,
    PatchGenerationError,
    PatchLLMError,
    PatchSyntaxError,
    PatchValidationError,
    RedactionError,
    SourceMismatchError,
    UnsafePatchError,
)
from .prompts import SYSTEM_PROMPT, build_messages
from .schema import (
    NewDependency,
    PatchCandidate,
    PatchedSource,
    PatchGeneration,
    PatchProposal,
    SourceSerializationError,
)

__all__ = [
    "SYSTEM_PROMPT",
    "ContextTooLargeError",
    "DiffApplyError",
    "DiffFormatError",
    "DiffHunkError",
    "DiffPathError",
    "DiffScopeError",
    "EmptyDiffError",
    "InsufficientContextError",
    "InvalidDiffError",
    "InvalidFindingError",
    "MalformedPatchResponseError",
    "MultiFileDiffError",
    "NewDependency",
    "NoOpDiffError",
    "ParsedDiff",
    "PatchCandidate",
    "PatchContext",
    "PatchGeneration",
    "PatchGenerationError",
    "PatchGeneratorAgent",
    "PatchLLMError",
    "PatchProposal",
    "PatchSyntaxError",
    "PatchValidationError",
    "PatchedSource",
    "RedactionError",
    "SourceMismatchError",
    "SourceSerializationError",
    "UnsafePatchError",
    "apply_diff",
    "build_messages",
    "build_patch_context",
    "parse_unified_diff",
]
