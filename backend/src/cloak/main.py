from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from cloak.benchmark import BenchmarkCondition, benchmark_candidate, case_by_id
from cloak.controller import Controller, validate_attack_result
from cloak.demo import recorded_demo
from cloak.models import (
    BenchmarkAttackRequest,
    BenchmarkAttackResponse,
    CausalRequest,
    CausalResult,
    ConfirmSessionRequest,
    ConfirmSessionResponse,
    HealthResponse,
    RestoreRequest,
    RestoreResult,
    SanitizedEnvelope,
    SessionCreateRequest,
    SessionCreateResponse,
)
from cloak.services.attacker import OpenAIAttacker
from cloak.services.ollama import OllamaAnonymizer
from cloak.sessions import Session, SessionStore

app = FastAPI(
    title="Cloak local controller",
    version="0.1.0",
    description="Loopback-only API. Document bodies are never written to logs or disk.",
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)

store = SessionStore()
attacker = OpenAIAttacker()
anonymizer = OllamaAnonymizer()
controller = Controller(attacker=attacker, anonymizer=anonymizer)


def _session(session_id: str) -> Session:
    try:
        return store.get(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    ollama_ready = await anonymizer.ready()
    attacker_ready = attacker.ready
    return HealthResponse(
        status="ready" if ollama_ready and attacker_ready else "degraded",
        ollama_ready=ollama_ready,
        ollama_model=anonymizer.model,
        attacker_ready=attacker_ready,
    )


@app.post("/api/sessions", response_model=SessionCreateResponse)
async def create_session(request: SessionCreateRequest) -> SessionCreateResponse:
    try:
        return store.create(request.text)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/sessions/{session_id}/confirm", response_model=ConfirmSessionResponse)
async def confirm_session(session_id: str, request: ConfirmSessionRequest) -> ConfirmSessionResponse:
    try:
        return store.confirm(session_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/sessions/{session_id}/runs")
async def run_session(session_id: str) -> StreamingResponse:
    session = _session(session_id)

    async def stream() -> AsyncIterator[str]:
        async for item in controller.run(session):
            yield item

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@app.post("/api/sessions/{session_id}/runs/{run_id}/causal", response_model=CausalResult)
async def causal_test(session_id: str, run_id: str, request: CausalRequest) -> CausalResult:
    session = _session(session_id)
    if session.last_run_id != run_id:
        raise HTTPException(status_code=409, detail="Causal tests apply only to the latest run.")
    try:
        return await controller.causal_test(session, request.quote)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Causal test stopped: {type(exc).__name__}") from exc


@app.post("/api/sessions/{session_id}/restore", response_model=RestoreResult)
async def restore(session_id: str, request: RestoreRequest) -> RestoreResult:
    session = _session(session_id)
    if session.candidate is None:
        raise HTTPException(status_code=409, detail="Confirm a document before restoring surrogates.")
    return session.vault.restore(request.text)


@app.delete("/api/sessions/{session_id}", status_code=204)
async def delete_session(session_id: str) -> Response:
    store.delete(session_id)
    return Response(status_code=204)


@app.get("/api/demo-runs/{slug}")
async def demo_run(slug: str) -> dict[str, object]:
    try:
        return recorded_demo(slug)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Recorded demo not found.") from exc


@app.post("/api/benchmark-smoke/{case_id}/{condition}", response_model=BenchmarkAttackResponse)
async def benchmark_smoke_attack(
    case_id: str,
    condition: BenchmarkCondition,
    request: BenchmarkAttackRequest,
) -> BenchmarkAttackResponse:
    """Attack one bundled synthetic fixture; the strict control body accepts no document text."""
    del request
    try:
        case = case_by_id(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Synthetic benchmark case not found.") from exc
    candidate = benchmark_candidate(case, condition)
    try:
        result = await attacker.attack(
            SanitizedEnvelope(
                candidate_text=candidate.text,
                candidate_sha256=candidate.sha256,
                phase="discovery",
            )
        )
        validate_attack_result(result)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Synthetic benchmark attack stopped: {type(exc).__name__}",
        ) from exc
    return BenchmarkAttackResponse(
        case_id=case.case_id,
        condition=condition,
        candidate_sha256=candidate.sha256,
        detected_direct_identifiers=len(candidate.detected_values),
        detected_entity_types=candidate.detected_entity_types,
        attack=result,
    )
