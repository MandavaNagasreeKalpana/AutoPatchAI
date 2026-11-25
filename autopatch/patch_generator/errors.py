"""Patch Generator errors.

Messages are short and safe to show: they never contain source code, raw
model output, secrets, or chained library exceptions.
"""

from __future__ import annotations


class PatchGenerationError(Exception):
    """Base class for all patch-generation failures."""


# -- inputs -----------------------------------------------------------------------


class InvalidFindingError(PatchGenerationError):
    """The finding is missing, of the wrong type, or unsupported."""


class InsufficientContextError(PatchGenerationError):
    """Source context is missing, unparseable, or lacks an AST span."""


class SourceMismatchError(InsufficientContextError):
    """The supplied source does not match the finding (stale scan?)."""


class ContextTooLargeError(PatchGenerationError):
    """The source or context exceeds the configured bounds (never truncated)."""


class RedactionError(PatchGenerationError):
    """Secrets could not be reliably removed before contacting the LLM."""


# -- LLM ------------------------------------------------------------------------


class PatchLLMError(PatchGenerationError):
    """The Groq request failed (auth, rate limit, quota, network, server...)."""

    def __init__(
        self,
        message: str,
        *,
        llm_error: str,
        retryable: bool = False,
        quota_exhausted: bool = False,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.llm_error = llm_error
        self.retryable = retryable
        self.quota_exhausted = quota_exhausted
        self.status_code = status_code


class MalformedPatchResponseError(PatchGenerationError):
    """The model's structured response was empty, invalid, or inconsistent."""


# -- diff -------------------------------------------------------------------------


class InvalidDiffError(PatchGenerationError):
    """Base class for unified-diff problems."""


class DiffFormatError(InvalidDiffError):
    """The text is not a well-formed single-file unified diff."""


class DiffPathError(InvalidDiffError):
    """The diff targets a different, absolute, or traversing path."""


class MultiFileDiffError(InvalidDiffError):
    """The diff touches more than one file."""


class EmptyDiffError(InvalidDiffError):
    """The diff has no hunks."""


class NoOpDiffError(InvalidDiffError):
    """The diff makes no actual change."""


class DiffHunkError(InvalidDiffError):
    """A hunk is malformed or its line counts do not match its header."""


class DiffApplyError(InvalidDiffError):
    """The diff does not apply cleanly to the supplied source."""


class DiffScopeError(InvalidDiffError):
    """The diff changes lines that were not shown to the model."""


# -- patched code -------------------------------------------------------------------


class PatchValidationError(PatchGenerationError):
    """The patched code failed a static (non-executing) check."""


class PatchSyntaxError(PatchValidationError):
    """The patched file is not valid Python syntax."""


class UnsafePatchError(PatchValidationError):
    """The patch adds dangerous constructs, undeclared dependencies, or
    copies a redaction placeholder into code."""
