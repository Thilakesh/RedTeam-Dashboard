"""Shared base for request (input) schemas.

Response/output schemas never parse untrusted input and don't need this —
only schemas that deserialize a client-supplied request body should extend
StrictRequest, so an unrecognized field is rejected (422) instead of
silently ignored. Handlers already map fields explicitly rather than
mass-assigning, so this is defense-in-depth, not a fix for a live bug.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
