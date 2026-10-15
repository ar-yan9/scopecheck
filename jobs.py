"""Single background job and bounded local history. No public job service."""

import json
from pathlib import Path
import sqlite3
import threading
import time
import uuid
from engine import execute


class Jobs:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.jobs = {}
        self.active = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, created REAL, payload TEXT)"
            )

    def db(self):
        return sqlite3.connect(self.path)

    def start(self, plan, selected, **kwargs):
        with self.lock:
            if self.active:
                raise ValueError("One scan is already running; cancel it or wait")
            id = uuid.uuid4().hex
            cancel = threading.Event()
            self.active = id
            self.jobs[id] = {
                "id": id,
                "status": "running",
                "progress": {"phase": "queued", "completed": 0, "total": len(selected)},
                "cancel": cancel,
            }
            thread = threading.Thread(
                target=self.run, args=(id, plan, selected, kwargs), daemon=True
            )
            thread.start()
            return id

    def run(self, id, plan, selected, kwargs):
        def progress(state):
            with self.lock:
                self.jobs[id]["progress"] = state

        try:
            report = execute(
                plan,
                selected,
                cancel=self.jobs[id]["cancel"],
                progress=progress,
                **kwargs
            )
            with self.db() as db:
                db.execute(
                    "DELETE FROM reports WHERE created < ?", (time.time() - 7 * 86400,)
                )
                db.execute(
                    "INSERT INTO reports VALUES(?,?,?)",
                    (id, time.time(), json.dumps(report)),
                )
                db.execute(
                    "DELETE FROM reports WHERE id NOT IN (SELECT id FROM reports ORDER BY created DESC LIMIT 20)"
                )
            with self.lock:
                self.jobs[id].update(
                    status=report["status"], report=report, finished_at=time.time()
                )
        except Exception as exc:
            with self.lock:
                self.jobs[id].update(
                    status="failed", error=str(exc), finished_at=time.time()
                )
        finally:
            with self.lock:
                self.active = None
                # Keep one last live job; older completed reports live in bounded SQLite.
                for key in list(self.jobs):
                    if key != id:
                        self.jobs.pop(key, None)

    def prune(self):
        cutoff = time.time() - 7 * 86400
        with self.lock:
            for key, value in list(self.jobs.items()):
                if value.get("finished_at", time.time()) < cutoff:
                    self.jobs.pop(key, None)
            with self.db() as db:
                db.execute("DELETE FROM reports WHERE created < ?", (cutoff,))

    def get(self, id):
        self.prune()
        with self.lock:
            if id in self.jobs:
                return {k: v for k, v in self.jobs[id].items() if k != "cancel"}
        with self.db() as db:
            row = db.execute("SELECT payload FROM reports WHERE id=?", (id,)).fetchone()
        if row:
            report = json.loads(row[0])
            return {"id": id, "status": report["status"], "report": report}
        return None

    def cancel(self, id):
        with self.lock:
            if id in self.jobs and self.jobs[id]["status"] == "running":
                self.jobs[id]["cancel"].set()
                return True
        return False

    def history(self):
        self.prune()
        with self.db() as db:
            db.execute(
                "DELETE FROM reports WHERE created < ?", (time.time() - 7 * 86400,)
            )
            rows = db.execute(
                "SELECT id,payload FROM reports ORDER BY created DESC"
            ).fetchall()
        return [
            {
                "id": id,
                "target": r["scope"]["target"],
                "created_utc": r["created_utc"],
                "status": r["status"],
                "summary": r["summary"],
                "coverage": r["coverage"],
            }
            for id, raw in rows
            for r in [json.loads(raw)]
        ]

    def clear(self):
        with self.lock:
            with self.db() as db:
                db.execute("DELETE FROM reports")
            self.jobs = {k: v for k, v in self.jobs.items() if v["status"] == "running"}
