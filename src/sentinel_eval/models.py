"""Pydantic models shared across the sentinel-eval harness."""

from __future__ import annotations

from pydantic import BaseModel, Field


class UserPersona(BaseModel):
    """A synthetic user with group memberships used for authorization checks."""

    user_id: str
    name: str
    groups: list[str] = Field(default_factory=list)


class DocumentMetadata(BaseModel):
    """ACL metadata for a single corpus document."""

    filename: str
    classification: str
    allowed_groups: list[str] = Field(default_factory=list)
    canary_tokens: list[str] = Field(default_factory=list)
    path: str


class DerivedContextNode(BaseModel):
    """A synthesized context node and the documents it was derived from."""

    node_id: str
    source_documents: list[str] = Field(default_factory=list)
    synthesized_text: str = ""


class AuditResult(BaseModel):
    """Outcome of auditing a single derived-context synthesis event."""

    query: str
    persona: UserPersona
    source_documents: list[str] = Field(default_factory=list)
    is_lineage_authorized: bool
    unauthorized_sources: list[str] = Field(default_factory=list)
    leaked_canaries: list[str] = Field(default_factory=list)
    privilege_escalation_detected: bool
    synthesized_output: str = ""
