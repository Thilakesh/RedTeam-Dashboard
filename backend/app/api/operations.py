"""Operations Console API — standalone manual scans.

Global (not per-target). Tenant isolation via Operation.org_id == user.org_id.
"""
from __future__ import annotations

import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, get_current_user
from app.core import features
from app.core.config import get_settings
from app.core.db import get_db
from app.models import Operation
from app.services import audit, storage
from app.schemas.operation import (
    CommandPreviewResponse,
    OperationCreateRequest,
    OperationDetailOut,
    OperationFindingOut,
    OperationOut,
    OperationPreviewRequest,
    OperationsResponse,
)
from app.services import operations as op_service
from app.services.operations import DuplicateOperationError, TooManyActiveOperationsError
from app.services.rate_limit import check_rate_limit

router = APIRouter(prefix="/operations", tags=["operations"])


def _op_out(op: Operation) -> OperationOut:
    return OperationOut(
        id=op.id,
        target=op.target,
        target_type=op.target_type,
        tool=op.tool,
        profile=op.profile,
        protocol=op.protocol,
        custom_args=op.custom_args,
        generated_command=op.generated_command,
        status=op.status,
        progress_pct=op.progress_pct,
        duration_s=op_service.duration_seconds(op),
        raw_output_present=op.raw_output is not None,
        exit_code=op.exit_code,
        error=op.error,
        created_at=op.created_at,
        started_at=op.started_at,
        completed_at=op.completed_at,
    )


async def _get_op_for_user(
    operation_id: UUID, db: AsyncSession, user: CurrentUser
) -> Operation:
    op = await op_service.get_operation(db, user.org_id, operation_id)
    if op is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "operation not found")
    if op.created_by != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "you do not have access to this operation")
    return op


@router.post("/preview", response_model=CommandPreviewResponse)
async def preview_operation(
    req: OperationPreviewRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CommandPreviewResponse:
    await features.require(db, user.id, "operations")
    if req.tool in features.FEATURES:
        await features.require(db, user.id, req.tool)
    try:
        cmd = op_service.build_preview(
            target_type=req.target_type,
            target=req.target,
            tool=req.tool,
            profile=req.profile,
            protocol=req.protocol,
            custom_args=req.custom_args,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))
    return CommandPreviewResponse(generated_command=cmd)


@router.post("", response_model=OperationOut, status_code=status.HTTP_201_CREATED)
async def create_operation(
    req: OperationCreateRequest,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OperationOut:
    allowed = await check_rate_limit(
        f"ratelimit:create_operation:{user.id}", limit=5, window_seconds=60
    )
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many operation creation requests — try again in a minute",
        )

    await features.require(db, user.id, "operations")
    if req.tool in features.FEATURES:
        await features.require(db, user.id, req.tool)
    try:
        op = await op_service.create_operation(
            db,
            org_id=user.org_id,
            created_by=user.id,
            target_type=req.target_type,
            target=req.target,
            tool=req.tool,
            profile=req.profile,
            protocol=req.protocol,
            custom_args=req.custom_args,
        )
    except TooManyActiveOperationsError as e:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(e))
    except DuplicateOperationError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))
    await audit.log(
        db,
        actor_user_id=user.id,
        action="operation.started",
        target_type="operation",
        target_id=op.id,
        meta={"target": op.target, "tool": op.tool},
        request=request,
    )
    return _op_out(op)


@router.get("", response_model=OperationsResponse)
async def list_operations(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OperationsResponse:
    rows = await op_service.list_operations(db, user.org_id, user.id)
    return OperationsResponse(rows=[_op_out(op) for op in rows])


@router.get("/{operation_id}", response_model=OperationDetailOut)
async def get_operation(
    operation_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OperationDetailOut:
    op = await _get_op_for_user(operation_id, db, user)
    findings = await op_service.get_operation_findings(db, op.id)
    return OperationDetailOut(
        operation=_op_out(op),
        findings=[
            OperationFindingOut(
                id=f.id,
                operation_id=f.operation_id,
                kind=f.kind,
                severity=f.severity,
                title=f.title,
                description=f.description,
                evidence=f.evidence or {},
                created_at=f.created_at,
            )
            for f in findings
        ],
        raw_output=op.raw_output,
        stderr=op.stderr,
        stdout_url=storage.object_url(op.stdout_object_key) if op.stdout_object_key else None,
        stderr_url=storage.object_url(op.stderr_object_key) if op.stderr_object_key else None,
    )


@router.post("/{operation_id}/cancel", response_model=OperationOut)
async def cancel_operation(
    operation_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OperationOut:
    op = await _get_op_for_user(operation_id, db, user)
    try:
        await op_service.cancel_operation(db, op)
    except ValueError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))

    redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        await redis.publish(
            f"operation:{operation_id}",
            json.dumps({"event": "operation.cancelled", "operation_id": str(operation_id)}),
        )
    finally:
        await redis.aclose()
    return _op_out(op)


@router.post(
    "/{operation_id}/retry",
    response_model=OperationOut,
    status_code=status.HTTP_201_CREATED,
)
async def retry_operation(
    operation_id: UUID,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OperationOut:
    op = await _get_op_for_user(operation_id, db, user)
    new = await op_service.retry_operation(db, op, created_by=user.id)
    await audit.log(
        db,
        actor_user_id=user.id,
        action="operation.retried",
        target_type="operation",
        target_id=new.id,
        meta={"target": new.target, "tool": new.tool, "retried_from": str(operation_id)},
        request=request,
    )
    return _op_out(new)
