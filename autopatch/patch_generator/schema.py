"""Patch Generator data structures.

Two strictly separated outputs:

* ``PatchCandidate`` is **report-safe**. It holds the M1 ``Patch`` (redacted
  view for credential findings), the validated ``PatchProposal`` and
  metadata. It contains no real source and may be serialized normally
  (``dataclasses.asdict``, pickle, Pydantic).
* ``PatchedSource`` is **execution-only**. It holds the real patched file
  (unchanged lines restored, which may include other real secrets) for the
  future Verification Agent's in-memory sandbox hand-off. It refuses every
  form of copying, pickling and Pydantic serialization, has no ``__dict__``,
  and never shows its content in ``repr``/``str``. Read it explicitly with
  :meth:`PatchedSource.reveal_for_verification`.

``PatchGeneratorAgent.generate`` returns a ``PatchGeneration`` pairing the
two. Report writers must only ever persist ``.candidate``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any, NoReturn

from pydantic import Field
from pydantic_core import core_schema

from autopatch.llm import TokenUsage
from autopatch.models import Patch, VulnerabilityCategory
from autopatch.models.common import Confidence, Identifier, NonEmptyStr, StrictModel, Text

MAX_DIFF_CHARS = 50_000
MAX_LIST_ITEMS = 20


class NewDependency(StrictModel):
    module: NonEmptyStr
    justification: NonEmptyStr


class PatchProposal(StrictModel):
    """Structured response requested from the LLM (unknown keys are rejected)."""

    finding_id: Identifier
    category: VulnerabilityCategory
    vulnerability_summary: NonEmptyStr
    remediation_rationale: NonEmptyStr
    unified_diff: Annotated[str, Field(min_length=1, max_length=MAX_DIFF_CHARS)]
    security_improvements: list[NonEmptyStr] = Field(min_length=1, max_length=MAX_LIST_ITEMS)
    assumptions: list[Text] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    limitations: list[Text] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    new_dependencies: list[NewDependency] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    confidence: Confidence  # the model's own estimate; NOT a verification result


class SourceSerializationError(TypeError):
    """Raised on any attempt to copy or serialize a ``PatchedSource``."""


class PatchedSource:
    """Execution-only, in-memory holder for the real patched file."""

    __slots__ = ("_text", "_patch_id", "_target_file")

    def __init__(self, text: str, *, patch_id: str, target_file: str) -> None:
        object.__setattr__(self, "_text", text)
        object.__setattr__(self, "_patch_id", patch_id)
        object.__setattr__(self, "_target_file", target_file)

    @property
    def patch_id(self) -> str:
        return self._patch_id

    @property
    def target_file(self) -> str:
        return self._target_file

    def reveal_for_verification(self) -> str:
        """Return the real patched file. Only for the in-memory verification
        hand-off; never log, persist or send the result anywhere."""
        return self._text

    def __len__(self) -> int:
        return len(self._text)

    def __setattr__(self, name: str, value: Any) -> NoReturn:
        raise AttributeError("PatchedSource is immutable.")

    def __repr__(self) -> str:
        return (
            f"PatchedSource(patch_id={self._patch_id!r}, target_file={self._target_file!r}, "
            f"<{len(self._text)} characters hidden>)"
        )

    __str__ = __repr__

    def _refuse(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise SourceSerializationError(
            "PatchedSource holds real source code (possibly including secrets) and cannot be "
            "copied, pickled or serialized. Persist only PatchGeneration.candidate."
        )

    __reduce__ = _refuse
    __reduce_ex__ = _refuse
    __getstate__ = _refuse
    __copy__ = _refuse
    __deepcopy__ = _refuse

    @classmethod
    def __get_pydantic_core_schema__(cls, source: Any, handler: Any) -> core_schema.CoreSchema:
        def refuse_serialization(value: Any) -> NoReturn:
            raise SourceSerializationError("PatchedSource cannot be serialized.")

        return core_schema.is_instance_schema(
            cls,
            serialization=core_schema.plain_serializer_function_ser_schema(refuse_serialization),
        )


@dataclass(frozen=True)
class PatchCandidate:
    """Report-safe, UNVERIFIED candidate patch. Contains no real source."""

    patch: Patch
    proposal: PatchProposal
    warnings: tuple[str, ...]
    usage: TokenUsage
    llm_attempts: int

    @property
    def verified(self) -> bool:
        return False  # only the Verification Agent may establish this

    def __repr__(self) -> str:  # identifiers and status only, never code
        return (
            f"PatchCandidate(patch_id={self.patch.patch_id!r}, finding_id={self.patch.finding_id!r}, "
            f"target_file={self.patch.target_file!r}, status={self.patch.status.value!r}, "
            f"attempt={self.patch.attempt}, warnings={len(self.warnings)}, verified=False)"
        )


@dataclass(frozen=True, repr=False)
class PatchGeneration:
    """Return value of ``PatchGeneratorAgent.generate``.

    ``candidate`` is report-safe; ``patched_source`` is execution-only.
    Copying or serializing the whole object fails explicitly because of
    ``patched_source``.
    """

    candidate: PatchCandidate
    patched_source: PatchedSource

    def __repr__(self) -> str:
        return f"PatchGeneration(candidate={self.candidate!r}, patched_source={self.patched_source!r})"
