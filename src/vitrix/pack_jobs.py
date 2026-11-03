"""Background jobs for content packs (ADR 0004): in memory, one running job per server.

A job downloads (or reuses the cached) SigmaHQ archive, scans it in memory and either reports the
candidates (`preview`) or turns the selected ones into drafts (`import`). State is lost on restart;
the cached archive stays. Stdlib only.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

KEEP_JOBS = 20
KEEP_SECONDS = 3600
ACTIVE = ("queued", "downloading", "scanning", "importing")


class JobBusy(Exception):
    """Another job is still running."""


@dataclass
class Job:
    id: str
    mode: str
    created_by: dict | None
    created_at: float
    state: str = "queued"
    progress: dict = field(default_factory=lambda: {"bytes": 0, "total": None, "scanned": 0, "matched": 0, "imported": 0})
    error: str | None = None
    finished_at: float | None = None
    result: dict | None = None

    def public(self) -> dict:
        def iso(ts: float) -> str:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))

        return {"id": self.id, "mode": self.mode, "state": self.state, "progress": dict(self.progress), "error": self.error,
                "created_by": self.created_by, "created_at": iso(self.created_at),
                "finished_at": iso(self.finished_at) if self.finished_at else None, "result": self.result}


class PackJobs:
    def __init__(self, clock: Callable[[], float] = time.time):
        self._now = clock
        self._lock = threading.Lock()
        self._jobs: dict[str, Job] = {}

    def running(self) -> bool:
        with self._lock:
            return any(j.state in ACTIVE for j in self._jobs.values())

    def start(self, mode: str, created_by: dict | None, work: Callable[[Job], None], *, background: bool = True) -> Job:
        """Register a job and run `work(job)` in a thread; raises JobBusy if one is active."""
        with self._lock:
            if any(j.state in ACTIVE for j in self._jobs.values()):
                raise JobBusy("another pack import is running")
            job = Job(id=uuid.uuid4().hex, mode=mode, created_by=created_by, created_at=self._now())
            self._jobs[job.id] = job
            self._prune()

        def run() -> None:
            try:
                work(job)
                job.state = "done"
            except Exception as exc:  # noqa: BLE001 - any failure is reported on the job, never raised into the thread
                job.state, job.error = "failed", str(exc)[:500] or exc.__class__.__name__
            finally:
                job.finished_at = self._now()

        if background:
            threading.Thread(target=run, name=f"pack-job-{job.id[:8]}", daemon=True).start()
        else:
            run()
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def _prune(self) -> None:
        now = self._now()
        for jid, j in list(self._jobs.items()):
            if j.finished_at and now - j.finished_at > KEEP_SECONDS:
                del self._jobs[jid]
        finished = [j for j in self._jobs.values() if j.finished_at]
        for j in sorted(finished, key=lambda x: x.created_at)[: max(0, len(self._jobs) - KEEP_JOBS)]:
            del self._jobs[j.id]
