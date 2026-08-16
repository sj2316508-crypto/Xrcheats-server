"""Render-ready FastAPI service for resolving vplink.in short links."""

from __future__ import annotations

import asyncio
import os
import time
import traceback
import uuid

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from bypass import SUPPORTED, bypass

TIMEOUT = int(os.getenv("BYPASS_TIMEOUT", "420"))
SYNC_BUDGET = float(os.getenv("SYNC_BUDGET", "20"))
CACHE_TTL = int(os.getenv("CACHE_TTL", "300"))
API_KEY = os.getenv("API_KEY", "").strip()

app = FastAPI(title="Bypass API", version="2.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

JOBS: dict[str, dict] = {}
RESULT_CACHE: dict[str, dict] = {}
ACTIVE_JOBS: dict[str, str] = {}
LOCK = asyncio.Semaphore(int(os.getenv("MAX_CONCURRENCY", "2")))


class BypassBody(BaseModel):
    url: str | None = None
    bypass: str | None = None
    key: str | None = None


def _error(message: str, code: int = 400, **extra):
    return JSONResponse(
        {"success": False, "status": "error", "error": message, **extra},
        status_code=code,
    )


def _normalize(value: str) -> str:
    value = value.strip().strip("\"'")
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    return value


def _check_key(key: str | None):
    if API_KEY and key != API_KEY:
        return _error("Invalid API key.", 403)
    return None


def _payload(job_id: str) -> dict:
    job = JOBS[job_id]
    result = {
        "success": job.get("success", False),
        "status": job.get("status", "running"),
        "source": job["source"],
        "job_id": job_id,
        "took": round(time.time() - job["started"], 1),
    }
    for key in ("bypassed", "error"):
        if key in job:
            result[key] = job[key]
    if result["status"] == "running":
        result["pending"] = True
        result["poll"] = f"/job?id={job_id}"
    return result


async def _worker(job_id: str, source: str):
    job = JOBS[job_id]
    try:
        async with LOCK:
            destination = await asyncio.wait_for(bypass(source), timeout=TIMEOUT)
        job.update(status="done", success=True, bypassed=destination)
        RESULT_CACHE[source] = {"bypassed": destination, "stored": time.time()}
    except asyncio.TimeoutError:
        job.update(status="error", success=False, error="Bypass timed out")
    except Exception as error:  # noqa: BLE001
        traceback.print_exc()
        job.update(
            status="error",
            success=False,
            error=f"{type(error).__name__}: {error}",
        )
    finally:
        job["took"] = round(time.time() - job["started"], 1)
        if ACTIVE_JOBS.get(source) == job_id:
            ACTIVE_JOBS.pop(source, None)


async def _start(source: str):
    cached = RESULT_CACHE.get(source)
    if cached and time.time() - cached["stored"] <= CACHE_TTL:
        return {
            "success": True,
            "status": "done",
            "source": source,
            "job_id": "cached",
            "took": 0,
            "bypassed": cached["bypassed"],
            "cached": True,
        }

    active = ACTIVE_JOBS.get(source)
    if active and JOBS.get(active, {}).get("status") == "running":
        return _payload(active)

    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {
        "source": source,
        "started": time.time(),
        "status": "running",
        "success": False,
    }
    ACTIVE_JOBS[source] = job_id
    task = asyncio.create_task(_worker(job_id, source))
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=SYNC_BUDGET)
    except asyncio.TimeoutError:
        pass
    return _payload(job_id)


@app.get("/")
async def info():
    return {
        "name": "Bypass API",
        "version": "2.1.0",
        "supported": SUPPORTED,
        "endpoints": ["/health", "/bypass", "/api", "/job", "/jobs"],
    }


@app.get("/health")
async def health():
    return {"ok": True}


@app.get("/bypass")
async def bypass_get(
    url: str | None = Query(default=None),
    bypass: str | None = None,
    key: str | None = None,
):
    key_error = _check_key(key)
    if key_error:
        return key_error
    value = url or bypass
    if not value:
        return _error("Missing url. Use ?url=<shortlink>.", 422)
    return await _start(_normalize(value))


@app.get("/api")
async def api_alias(
    bypass: str | None = None,
    url: str | None = None,
    key: str | None = None,
):
    key_error = _check_key(key)
    if key_error:
        return key_error
    value = bypass or url
    if not value:
        return _error("Missing bypass. Use ?bypass=<shortlink>.", 422)
    return await _start(_normalize(value))


@app.post("/bypass")
async def bypass_post(body: BypassBody):
    key_error = _check_key(body.key)
    if key_error:
        return key_error
    value = body.url or body.bypass
    if not value:
        return _error("Missing url in request body.", 422)
    return await _start(_normalize(value))


@app.get("/job")
async def job_get(id: str = Query(...)):
    if id not in JOBS:
        return _error("Unknown job id", 404)
    return _payload(id)


@app.get("/jobs")
async def jobs_get():
    return {"jobs": [_payload(job_id) for job_id in list(JOBS)[-25:]]}


# --- NEW ROUTE TO FIX 404 CONFIG ERROR ---
@app.get("/hawkdev/ongetlogindesc.php/{name}/{v1}/{v2}/{v3}/{v4}")
@app.get("/hawkdev/ongetlogindesc.php/{name}/{v1}/{v2}/{v3}/{v4}/")
def get_login_desc(name: str, v1: str, v2: str, v3: str, v4: str):
    return {
        "verAddr": f"https://xrcheats-server.onrender.com/hawkdev/ongetlogindesc.php/{name}/{v1}/{v2}/{v3}/{v4}/"
    }
