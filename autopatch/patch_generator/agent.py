"""Patch Generator Agent: one finding -> one UNVERIFIED candidate patch.

Pipeline (no file I/O, no code execution):
1. ``build_patch_context``: validate inputs; bounded, redacted context.
2. ``build_messages``: untrusted-data prompt with a random delimiter.
3. ``GroqClient.chat_json``: structured response validated as ``PatchProposal``.
4. ``parse_unified_diff`` + ``apply_diff``: strict single-file diff applied
   in memory to the exact source the model saw.
5. ``check_patched_source``: AST-only syntax, safety and category checks.
6. Build the M1 ``Patch`` (status GENERATED) with a canonical diff.
7. Return ``PatchGeneration``: report-safe ``candidate`` plus the
   execution-only ``patched_source`` holder for the Verification Agent.

Logs contain only identifiers, rule IDs, counts and error types.
"""

from __future__ import annotations

import difflib
import logging
import re
from collections.abc import Callable, Sequence
from typing import Any, Protocol

from pydantic import ValidationError

from autopatch.config import Settings
from autopatch.llm import (
    ChatMessage,
    GroqClient,
    LLMEmptyResponseError,
    LLMError,
    LLMRateLimitError,
    LLMStructuredOutputError,
    StructuredResult,
)
from autopatch.models import Finding, Patch, PatchStatus
from autopatch.redaction import REDACTED
from autopatch.common.source import REDACTED_LITERAL

from .context import PatchContext, build_patch_context
from .diff import apply_diff, parse_unified_diff
from .errors import (
    MalformedPatchResponseError,
    PatchGenerationError,
    PatchLLMError,
    UnsafePatchError,
)
from .prompts import build_messages, new_nonce
from .safety import check_patched_source
from .schema import PatchCandidate, PatchedSource, PatchGeneration, PatchProposal

logger = logging.getLogger("autopatch.patch_generator")

DEFAULT_MAX_TOKENS = 2048
_VERIFICATION_CLAIM = re.compile(
    r"(?i)\b(?<!un)(verified|guaranteed|fully secure|100% (?:safe|secure)|has been tested|is tested)\b"
)


class StructuredChatClient(Protocol):
    def chat_json(
        self,
        messages: Sequence[ChatMessage | dict[str, Any]],
        *,
        schema: type[PatchProposal] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> StructuredResult[Any]: ...


class PatchGeneratorAgent:
    """Generate candidate patches with the existing M3A Groq client."""

    def __init__(
        self,
        client: StructuredChatClient,
        *,
        temperature: float = 0.0,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        nonce_factory: Callable[[], str] = new_nonce,
    ) -> None:
        self._client = client
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._nonce_factory = nonce_factory

    @classmethod
    def from_settings(cls, settings: Settings, **kwargs: Any) -> PatchGeneratorAgent:
        """Build with a ``GroqClient``; raises ``MissingLLMConfigError`` if unset."""
        return cls(GroqClient(settings), **kwargs)

    def generate(
        self,
        finding: Finding,
        source: str,
        *,
        guidance: str | None = None,
        attempt: int = 1,
    ) -> PatchGeneration:
        """Return a :class:`PatchGeneration` (report-safe ``candidate`` plus
        execution-only ``patched_source``) or raise a
        :class:`PatchGenerationError` subclass. Never writes files or runs code."""
        finding_id = getattr(finding, "finding_id", "<unknown>")
        try:
            result = self._generate(finding, source, guidance=guidance, attempt=attempt)
        except PatchGenerationError as error:
            logger.warning("Patch generation failed for finding %s: %s", finding_id, type(error).__name__)
            raise
        candidate = result.candidate
        added, removed = self._stats(candidate)
        logger.info(
            "Generated UNVERIFIED candidate %s for finding %s (%s, %s): +%d/-%d lines, %d LLM attempt(s).",
            candidate.patch.patch_id,
            finding_id,
            candidate.patch.target_file,
            finding.rule_id,
            added,
            removed,
            candidate.llm_attempts,
        )
        return result

    # -- pipeline ---------------------------------------------------------------

    def _generate(self, finding: Finding, source: str, *, guidance: str | None, attempt: int) -> PatchGeneration:
        context = build_patch_context(finding, source)
        messages = build_messages(context, guidance=guidance, nonce_factory=self._nonce_factory)
        result = self._request(messages)
        proposal = result.parsed
        if not isinstance(proposal, PatchProposal):
            raise MalformedPatchResponseError("The model response was not a patch proposal.")
        if proposal.finding_id != finding.finding_id:
            raise MalformedPatchResponseError("The response refers to a different finding_id.")
        if proposal.category is not finding.category:
            raise MalformedPatchResponseError("The response refers to a different vulnerability category.")

        parsed = parse_unified_diff(proposal.unified_diff, context.target_file)
        if any(REDACTED in line or REDACTED_LITERAL in line for line in parsed.added_lines):
            raise UnsafePatchError(
                "The patch copies a redaction placeholder into the code instead of removing the secret."
            )
        applied = apply_diff(
            parsed,
            context.display_lines,
            context.original_lines,
            allowed_lines=context.shown_lines,
            newline=context.newline,
        )
        proposed_source = "".join(applied.real_lines)
        end_line = finding.end_line or finding.line
        warnings = check_patched_source(
            source,
            proposed_source,
            [d.module for d in proposal.new_dependencies],
            category=finding.category,
            flagged_lines=range(finding.line, end_line + 1),
            # With fallback redaction the values include non-secret literals,
            # so they cannot be used to prove the credential was removed.
            flagged_values=() if context.fallback_redaction else context.flagged_values,
        )
        if context.fallback_redaction:
            warnings.append(
                "The credential literal could not be identified precisely; every literal on the "
                "flagged lines was masked and removal of the credential was not checked locally."
            )
        warnings += list(context.notes)  # limits of the stale-source check, never silent
        warnings += self._claim_warnings(proposal)
        patch = self._build_patch(context, applied.display_lines, proposal, result, attempt)
        candidate = PatchCandidate(
            patch=patch,
            proposal=proposal,
            warnings=tuple(warnings),
            usage=result.raw.usage,
            llm_attempts=result.raw.attempts,
        )
        return PatchGeneration(
            candidate=candidate,
            patched_source=PatchedSource(proposed_source, patch_id=patch.patch_id, target_file=patch.target_file),
        )

    def _request(self, messages: list[ChatMessage]) -> StructuredResult[Any]:
        error: PatchGenerationError | None = None
        try:
            result = self._client.chat_json(
                messages,
                schema=PatchProposal,
                temperature=self._temperature,
                max_tokens=self._max_tokens,
            )
        except LLMStructuredOutputError as exc:
            # str(exc) never contains the raw response; exc.raw_content is NOT copied.
            error = MalformedPatchResponseError(f"The model response was not a valid patch proposal: {exc}")
        except LLMEmptyResponseError:
            error = MalformedPatchResponseError("The model returned an empty response.")
        except LLMError as exc:
            error = PatchLLMError(
                f"The LLM request failed: {exc}",
                llm_error=type(exc).__name__,
                retryable=exc.retryable,
                quota_exhausted=isinstance(exc, LLMRateLimitError) and exc.quota_exhausted,
                status_code=exc.status_code,
            )
        if error is not None:
            raise error from None  # raised outside the except block: no chained LLM error
        return result

    def _build_patch(
        self,
        context: PatchContext,
        patched_display: tuple[str, ...],
        proposal: PatchProposal,
        result: StructuredResult[Any],
        attempt: int,
    ) -> Patch:
        """Patch fields use the redacted view, so the record is report-safe."""
        before, after = list(context.display_lines), list(patched_display)
        target = context.target_file
        diff = "".join(
            line if line.endswith("\n") else line + "\n"
            for line in difflib.unified_diff(before, after, fromfile=f"a/{target}", tofile=f"b/{target}")
        )
        original_code, proposed_code = _changed_region(before, after)
        assumptions = [*proposal.assumptions, *(f"Limitation: {item}" for item in proposal.limitations)]
        payload = {
            "finding_id": context.finding.finding_id,
            "target_file": target,
            "original_code": original_code,
            "proposed_code": proposed_code,
            "explanation": proposal.remediation_rationale,
            "unified_diff": diff,
            "model_name": result.raw.model,
            "confidence": proposal.confidence,
            "assumptions": assumptions,
            "status": PatchStatus.GENERATED,
            "attempt": attempt,
        }
        error: PatchGenerationError | None = None
        try:
            patch = Patch.model_validate(payload)
        except ValidationError as exc:
            fields = ", ".join(sorted({str(e["loc"][0]) for e in exc.errors() if e["loc"]})) or "unknown"
            error = MalformedPatchResponseError(f"The generated patch failed validation (fields: {fields}).")
        if error is not None:
            raise error from None
        return patch

    @staticmethod
    def _claim_warnings(proposal: PatchProposal) -> list[str]:
        texts = [
            proposal.vulnerability_summary,
            proposal.remediation_rationale,
            *proposal.security_improvements,
        ]
        if any(_VERIFICATION_CLAIM.search(text) for text in texts):
            return ["The model text claims verification or guaranteed safety; ignored. The patch is UNVERIFIED."]
        return []

    @staticmethod
    def _stats(candidate: PatchCandidate) -> tuple[int, int]:
        lines = candidate.patch.unified_diff.splitlines()
        added = sum(1 for ln in lines if ln.startswith("+") and not ln.startswith("+++"))
        removed = sum(1 for ln in lines if ln.startswith("-") and not ln.startswith("---"))
        return added, removed


def _changed_region(before: list[str], after: list[str]) -> tuple[str, str]:
    """Smallest region covering every change, widened to non-blank text."""
    opcodes = [op for op in difflib.SequenceMatcher(a=before, b=after, autojunk=False).get_opcodes() if op[0] != "equal"]
    i1, i2 = min(op[1] for op in opcodes), max(op[2] for op in opcodes)
    j1, j2 = min(op[3] for op in opcodes), max(op[4] for op in opcodes)
    while not "".join(before[i1:i2]).strip():
        if i1 > 0:
            i1, j1 = i1 - 1, j1 - 1
        elif i2 < len(before):
            i2, j2 = i2 + 1, j2 + 1
        else:
            break
    return "".join(before[i1:i2]), "".join(after[j1:j2])
