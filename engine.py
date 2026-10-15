"""Bounded background scan engine, observable progress and cooperative cancellation."""

from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import datetime as dt
import socket
import threading
import time
from scanner import (
    ports,
    tcp_probe,
    tls_observation,
    http_observation,
    passive_banner,
    VERSION,
)
from profiles import HTTP_PORTS, TLS_PORTS, HTTPS_PORTS, PASSIVE_PORTS


class Cancelled(Exception):
    pass


class Gate:
    def __init__(self, rate, cancel):
        self.interval = 1 / rate
        self.cancel = cancel
        self.lock = threading.Lock()
        self.next = 0

    def wait(self):
        with self.lock:
            delay = max(0, self.next - time.monotonic())
            if self.cancel.wait(delay):
                raise Cancelled()
            self.next = time.monotonic() + self.interval


def service_hint(port, banner=None):
    text = (banner or {}).get("text", "")
    if text.startswith("SSH-"):
        return {"name": "ssh", "basis": "observed greeting", "verified_protocol": True}
    if text.startswith("220"):
        return {
            "name": "ftp-or-smtp",
            "basis": "ambiguous 220 greeting; needs review",
            "verified_protocol": False,
        }
    try:
        name = socket.getservbyport(port, "tcp")
    except OSError:
        name = "unknown"
    return {
        "name": name,
        "basis": "port-number registry hint only",
        "verified_protocol": False,
    }


def enrich(
    row, plan, timeout, gate, auto, http_ports, tls_ports, banner_ports, extended=False
):
    p = row["port"]
    checks = []
    if auto:
        # Never send arbitrary protocol probes to printers/databases/unknown services by default.
        http_ports = set(http_ports) | HTTP_PORTS | HTTPS_PORTS
        tls_ports = set(tls_ports) | TLS_PORTS
        banner_ports = set(banner_ports) | PASSIVE_PORTS
    if p in banner_ports or extended:
        row["banner"] = passive_banner(
            plan["selected_address"], p, min(timeout, 0.5), gate
        )
        checks.append("passive_banner")
    row["service"] = service_hint(p, row.get("banner"))
    if p in tls_ports:
        row["tls"] = tls_observation(
            plan["selected_address"], plan["target"], p, timeout, gate
        )
        checks.append("verified_tls_handshake")
    if p in http_ports:
        row["http"] = http_observation(
            plan["selected_address"],
            plan["target"],
            p,
            timeout,
            gate,
            tls=p in tls_ports,
        )
        checks.append("http_head")
        if row["http"]["status"] == "observed":
            row["service"] = {
                "name": "https" if p in tls_ports else "http",
                "basis": "observed HTTP response",
                "verified_protocol": True,
            }
    row["checks_run"] = checks
    if not checks:
        row["check_note"] = (
            "Unknown/non-web port: no arbitrary active HTTP/TLS probe. Use explicit protocol ports only with permission."
        )
    return row


def execute(
    plan,
    selected,
    timeout=1,
    workers=32,
    rate=50,
    auto=True,
    http_ports=(),
    tls_ports=(),
    banner_ports=(),
    extended=False,
    cancel=None,
    progress=None,
):
    cancel = cancel or threading.Event()
    progress = progress or (lambda x: None)
    if (
        not selected
        or len(set(selected)) != len(selected)
        or len(selected) > 65535
        or any(type(p) is not int or not 1 <= p <= 65535 for p in selected)
    ):
        raise ValueError("Choose 1-65535 distinct TCP ports")
    if (
        not 0.1 <= timeout <= 5
        or type(workers) is not int
        or not 1 <= workers <= 128
        or not 0.2 <= rate <= 200
    ):
        raise ValueError("Timeout .1-5s, workers 1-128, rate .2-200/s")
    if not plan.get("own_machine") and (workers > 16 or rate > 25):
        raise ValueError(
            "Non-owned scope is limited to 16 workers and 25 connections/s; use a lower rate required by the owner"
        )
    # Legacy/manual lists no longer break a scan: only their intersection is used.
    ignored = sorted(
        (set(http_ports) | set(tls_ports) | set(banner_ports)) - set(selected)
    )
    gate = Gate(rate, cancel)
    rows = []
    total = len(selected)
    completed = 0
    open_count = 0
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = {}
        iterator = iter(selected)

        def fill():
            while len(pending) < workers * 2 and not cancel.is_set():
                try:
                    p = next(iterator)
                except StopIteration:
                    break
                pending[
                    pool.submit(tcp_probe, plan["selected_address"], p, timeout, gate)
                ] = p

        fill()
        while pending:
            done, _ = wait(pending, timeout=0.2, return_when=FIRST_COMPLETED)
            for f in done:
                pending.pop(f)
                try:
                    row = f.result()
                except Cancelled:
                    continue
                rows.append(row)
                completed += 1
                if row["state"] == "open":
                    open_count += 1
            progress(
                {
                    "phase": "tcp",
                    "completed": completed,
                    "total": total,
                    "open": open_count,
                    "elapsed_seconds": round(time.monotonic() - started, 1),
                }
            )
            if cancel.is_set():
                for f in pending:
                    f.cancel()
                break
            fill()
    open_rows = [r for r in rows if r["state"] == "open"]
    enriched = 0
    if not cancel.is_set():
        # Bounded enrichments; every new connection still shares the rate gate.
        with ThreadPoolExecutor(max_workers=min(workers, 8)) as pool:
            iterator = iter(open_rows)
            pending = {}

            def add():
                while len(pending) < min(workers, 8) and not cancel.is_set():
                    try:
                        r = next(iterator)
                    except StopIteration:
                        break
                    pending[
                        pool.submit(
                            enrich,
                            r,
                            plan,
                            timeout,
                            gate,
                            auto,
                            http_ports,
                            tls_ports,
                            banner_ports,
                            extended,
                        )
                    ] = r

            add()
            while pending:
                done, _ = wait(pending, timeout=0.2, return_when=FIRST_COMPLETED)
                for f in done:
                    pending.pop(f)
                    try:
                        f.result()
                        enriched += 1
                    except Cancelled:
                        pass
                progress(
                    {
                        "phase": "checks",
                        "completed": completed,
                        "total": total,
                        "checks_completed": enriched,
                        "checks_total": len(open_rows),
                        "open": len(open_rows),
                        "elapsed_seconds": round(time.monotonic() - started, 1),
                    }
                )
                if cancel.is_set():
                    for f in pending:
                        f.cancel()
                    break
                add()
    rows.sort(key=lambda x: x["port"])
    return {
        "tool": "ScopeCheck",
        "version": VERSION,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scope": plan,
        "status": "cancelled" if cancel.is_set() else "completed",
        "configuration": {
            "port_count": total,
            "timeout_seconds": timeout,
            "workers": workers,
            "max_connections_per_second": rate,
            "automatic_checks": auto,
            "ignored_manual_ports": ignored,
        },
        "results": rows,
        "summary": {
            s: sum(r["state"] == s for r in rows)
            for s in ["open", "closed", "timeout", "error"]
        },
        "coverage": {
            "requested": total,
            "completed": len(rows),
            "unscanned": total - len(rows),
            "open_checked": enriched,
            "open_checks_pending": len(open_rows) - enriched,
        },
        "limits": [
            "Open ports/configuration observations are not confirmed vulnerabilities",
            "Single pinned DNS address; no UDP, exploitation, brute force or DoS",
            "Automatic active checks use explicit service-port hints; unknown services are not blindly probed",
            "A verified TLS negotiation does not enumerate all supported protocols/ciphers",
            "Timeout is unknown state, not proof of filtering; scans can trigger alerts or disturb fragile services",
            "Possible version hints cover only the documented Apache rules; absence means nothing about other CVEs",
        ],
    }
