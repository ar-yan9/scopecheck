import json, threading, time
from pathlib import Path
import pytest
import engine, scanner
from jobs import Jobs
from reports import render_html
from fastapi.testclient import TestClient
import app


def wait_job(manager, id):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        j = manager.get(id)
        if j["status"] != "running":
            return j
        time.sleep(0.01)
    pytest.fail("job did not settle")


def test_full_range_presets():
    assert scanner.ports("1-65535") == list(range(1, 65536))
    assert len(scanner.ports("common100")) == 100
    assert len(scanner.ports("first1000")) == 1000
    assert scanner.ports("all") == list(range(1, 65536))


def test_own_interfaces_not_private_subnet(monkeypatch):
    monkeypatch.setattr(
        scanner, "local_addresses", lambda: {"127.0.0.1", "192.168.1.25"}
    )
    monkeypatch.setattr(
        scanner.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("192.168.1.25", 0))],
    )
    assert scanner.resolve_plan("my-laptop")["own_machine"]
    monkeypatch.setattr(
        scanner.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("192.168.1.26", 0))],
    )
    with pytest.raises(ValueError):
        scanner.resolve_plan("other-device")
    assert not scanner.resolve_plan("other-device", True, ["192.168.1.26"])[
        "own_machine"
    ]


def test_mock_full65535_bounded_engine_no_network(monkeypatch):
    # A full-range engine regression with fake TCP probes, not a network sweep.
    monkeypatch.setattr(
        engine, "tcp_probe", lambda a, p, t, g: {"port": p, "state": "closed"}
    )
    states = []
    r = engine.execute(
        {
            "selected_address": "127.0.0.1",
            "target": "localhost",
            "own_machine": True,
            "resolved_addresses": ["127.0.0.1"],
        },
        list(range(1, 65536)),
        workers=64,
        rate=200,
        progress=states.append,
    )
    assert r["summary"]["closed"] == 65535
    assert r["coverage"]["unscanned"] == 0
    assert states[-1]["completed"] == 65535
    assert len(r["results"]) == 65535


def test_cancel_partial_coverage(monkeypatch):
    stop = threading.Event()

    def probe(a, p, t, g):
        g.wait()
        return {"port": p, "state": "closed"}

    monkeypatch.setattr(engine, "tcp_probe", probe)

    def progress(x):
        if x["completed"] >= 1:
            stop.set()

    r = engine.execute(
        {
            "selected_address": "127.0.0.1",
            "target": "localhost",
            "own_machine": True,
            "resolved_addresses": ["127.0.0.1"],
        },
        list(range(1, 101)),
        workers=2,
        rate=10,
        cancel=stop,
        progress=progress,
    )
    assert r["status"] == "cancelled" and r["coverage"]["unscanned"] > 0
    assert r["coverage"]["completed"] == len(r["results"])


def test_mismatched_overrides_ignored_no_validation_error(monkeypatch):
    monkeypatch.setattr(
        engine, "tcp_probe", lambda a, p, t, g: {"port": p, "state": "closed"}
    )
    r = engine.execute(
        {
            "selected_address": "127.0.0.1",
            "target": "localhost",
            "own_machine": True,
            "resolved_addresses": ["127.0.0.1"],
        },
        [22],
        http_ports=[8899],
        tls_ports=[443],
    )
    assert r["configuration"]["ignored_manual_ports"] == [443, 8899]


def test_no_blind_active_probe_unknown_port(monkeypatch):
    monkeypatch.setattr(
        engine, "http_observation", lambda *a, **k: pytest.fail("HTTP probe forbidden")
    )
    monkeypatch.setattr(
        engine, "tls_observation", lambda *a, **k: pytest.fail("TLS probe forbidden")
    )
    row = engine.enrich({"port": 9100, "state": "open"}, {}, 1, None, True, [], [], [])
    assert row["checks_run"] == [] and "no arbitrary" in row["check_note"]


def test_external_limits(monkeypatch):
    with pytest.raises(ValueError):
        engine.execute({"own_machine": False}, [80], workers=32)


def test_history_lifecycle_and_html_escaping(tmp_path, monkeypatch):
    monkeypatch.setattr(
        engine, "tcp_probe", lambda a, p, t, g: {"port": p, "state": "closed"}
    )
    import jobs

    original = jobs.execute

    def execute(*a, **k):
        r = original(*a, **k)
        r["scope"]["target"] = "<script>alert(1)</script>"
        return r

    monkeypatch.setattr(jobs, "execute", execute)
    manager = Jobs(tmp_path / "history.db")
    id = manager.start(
        {
            "selected_address": "127.0.0.1",
            "target": "localhost",
            "own_machine": True,
            "resolved_addresses": ["127.0.0.1"],
        },
        [1],
        workers=1,
        rate=10,
    )
    r = wait_job(manager, id)["report"]
    assert len(manager.history()) == 1
    assert "<script>alert(1)</script>" not in render_html(r)
    assert "&lt;script&gt;" in render_html(r)
    reloaded = Jobs(tmp_path / "history.db")
    assert reloaded.get(id)["report"]["summary"]["closed"] == 1
    reloaded.clear()
    assert reloaded.history() == [] and reloaded.get(id) is None


def test_job_api_progress_export_and_clear(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "manager", Jobs(tmp_path / "api-history.db"))
    monkeypatch.setattr(
        engine, "tcp_probe", lambda a, p, t, g: {"port": p, "state": "closed"}
    )
    with TestClient(app.app) as client:
        res = client.post(
            "/api/jobs",
            json={
                "target": "127.0.0.1",
                "ports": "1-20",
                "http_ports": "8899",
                "authorized": False,
            },
        )
        assert res.status_code == 200
        id = res.json()["id"]
        wait_job(app.manager, id)
        status = client.get("/api/jobs/" + id).json()
        assert "report" not in status
        report = client.get("/api/jobs/" + id + "/report").json()
        assert report["coverage"]["completed"] == 20
        assert report["configuration"]["ignored_manual_ports"] == [8899]
        assert client.get("/api/jobs/" + id + "/html").status_code == 200
        printable = client.get("/api/jobs/" + id + "/print")
        assert printable.status_code == 200 and "Save as PDF" in printable.text
        assert len(client.get("/api/history").json()["reports"]) == 1
        assert "127.0.0.1" in client.get("/api/local-addresses").json()["addresses"]
        assert client.post("/api/history/clear", json={}).status_code == 200
        assert client.get("/api/history").json()["reports"] == []


def test_cookie_values_never_reported():
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class CookieLab(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.send_header(
                "Set-Cookie",
                "session=DO_NOT_STORE_THIS; HttpOnly; Secure; SameSite=Lax",
            )
            self.send_header("Set-Cookie", "theme=ALSO_OMIT")
            self.end_headers()

        def log_message(self, *a):
            pass

    lab = HTTPServer(("127.0.0.1", 0), CookieLab)
    thread = threading.Thread(target=lab.serve_forever, daemon=True)
    thread.start()
    try:
        r = scanner.http_observation(
            "127.0.0.1", "localhost", lab.server_port, 1, scanner.RateGate(100)
        )
        assert len(r["cookies"]) == 2
        assert r["cookies"][0]["secure"] and r["cookies"][0]["httponly"]
        assert r["cookies"][0]["samesite"] == "Lax"
        assert "DO_NOT_STORE_THIS" not in json.dumps(
            r
        ) and "ALSO_OMIT" not in json.dumps(r)
    finally:
        lab.shutdown()
        thread.join()
        lab.server_close()


def test_single_active_job_conflict(tmp_path, monkeypatch):
    import jobs

    entered = threading.Event()
    release = threading.Event()
    original = jobs.execute

    def slow(*a, **k):
        entered.set()
        release.wait(2)
        return original(*a, **k)

    monkeypatch.setattr(jobs, "execute", slow)
    monkeypatch.setattr(
        engine, "tcp_probe", lambda a, p, t, g: {"port": p, "state": "closed"}
    )
    manager = Jobs(tmp_path / "h.db")
    plan = {
        "selected_address": "127.0.0.1",
        "target": "localhost",
        "own_machine": True,
        "resolved_addresses": ["127.0.0.1"],
    }
    id = manager.start(plan, [1])
    entered.wait(1)
    try:
        with pytest.raises(ValueError):
            manager.start(plan, [2])
    finally:
        release.set()
    wait_job(manager, id)


def test_history_retention_expired_live_and_saved(tmp_path, monkeypatch):
    import jobs

    monkeypatch.setattr(
        engine, "tcp_probe", lambda a, p, t, g: {"port": p, "state": "closed"}
    )
    manager = Jobs(tmp_path / "retention.db")
    id = manager.start(
        {"selected_address": "127.0.0.1", "target": "localhost", "own_machine": True},
        [1],
    )
    wait_job(manager, id)
    future = time.time() + 8 * 86400
    monkeypatch.setattr(jobs.time, "time", lambda: future)
    assert manager.get(id) is None
    assert manager.history() == []


def test_html_includes_all_open_ports_and_escapes_remote_text():
    report = {
        "scope": {
            "target": "localhost",
            "selected_address": "127.0.0.1",
            "resolved_addresses": ["127.0.0.1"],
        },
        "summary": {"open": 2, "closed": 0, "timeout": 0, "error": 0},
        "coverage": {
            "completed": 2,
            "requested": 2,
            "unscanned": 0,
            "open_checks_pending": 0,
        },
        "status": "completed",
        "version": "0.2.0",
        "created_utc": "fixture",
        "configuration": {},
        "limits": [],
        "results": [
            {
                "port": 80,
                "state": "open",
                "service": {"name": "<script>bad</script>", "basis": "fixture"},
            },
            {
                "port": 443,
                "state": "open",
                "tls": {
                    "status": "verified",
                    "subject": "<img src=x>",
                    "protocol": "TLSv1.3",
                },
            },
        ],
    }
    rendered = render_html(report)
    assert "80 / TCP / open" in rendered and "443 / TCP / open" in rendered
    assert "<script>bad</script>" not in rendered and "<img src=x>" not in rendered
    assert "&lt;img src=x&gt;" in rendered and "&lt;script&gt;" in rendered


def test_csv_export(tmp_path, monkeypatch):
    from reports import render_csv

    monkeypatch.setattr(
        engine,
        "tcp_probe",
        lambda a, p, t, g: (
            {
                "port": p,
                "state": "open",
                "connect_ms": 1.5,
                "service": {
                    "name": "http",
                    "basis": "observed HTTP response",
                    "verified_protocol": True,
                },
                "http": {
                    "status": "observed",
                    "response_status": 200,
                    "server_header": 'nginx, "quoted"',
                    "missing_headers": ["Content-Security-Policy", "X-Frame-Options"],
                },
                "checks_run": ["http_head"],
            }
            if p == 80
            else {"port": p, "state": "closed"}
        ),
    )
    monkeypatch.setattr(app, "manager", Jobs(tmp_path / "csv-history.db"))
    monkeypatch.setattr(engine, "enrich", lambda row, *a, **k: row)
    with TestClient(app.app) as client:
        res = client.post(
            "/api/jobs",
            json={"target": "127.0.0.1", "ports": "80-82", "authorized": False},
        )
        assert res.status_code == 200
        id = res.json()["id"]
        wait_job(app.manager, id)
        r = client.get("/api/jobs/" + id + "/report.csv")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/csv")
        assert "scopecheck-report.csv" in r.headers["content-disposition"]
        lines = r.text.splitlines()
        assert lines[0].startswith("target,created_utc,port,state")
        assert len(lines) == 4  # header + 3 ports
        row80 = [l for l in lines if ",80,open," in l][0]
        assert "observed HTTP response" in row80
        assert '"nginx, ""quoted"""' in row80  # csv quoting escapes commas/quotes
        assert "Content-Security-Policy; X-Frame-Options" in row80
        assert sum(1 for l in lines if ",closed," in l) == 2
        # unit-level: csv parses back cleanly
        import csv as csvmod, io

        report = wait_job(app.manager, id)["report"]
        rows = list(csvmod.reader(io.StringIO(render_csv(report))))
        assert rows[1][4] == "1.5" and rows[1][9] == "200"
        # 404 paths
        assert client.get("/api/jobs/nope/report.csv").status_code == 404
