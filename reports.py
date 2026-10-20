"""Self-contained escaped evidence report. Browser Print > Save as PDF, no third party."""

import html, json


def render_html(report):
    esc = lambda x: html.escape(str(x), quote=True)
    scope = report["scope"]
    summary = report["summary"]
    coverage = report["coverage"]

    def text(label, value):
        return "<p><b>" + esc(label) + ":</b> " + esc(value) + "</p>"

    parts = [
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src \'none\'; base-uri \'none\'"><title>ScopeCheck evidence report</title><style>body{font:14px/1.6 system-ui;margin:40px auto;max-width:900px;padding:0 22px;color:#233a2b}h1{font-size:34px;letter-spacing:-.045em}h2{font-size:23px;letter-spacing:-.03em}h3{font-size:16px}article{border-top:2px solid #9fb393;padding:18px 0;margin:22px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:10px}p,li{overflow-wrap:anywhere}.kicker{font:10px monospace;letter-spacing:.12em;color:#6a835d}.callout{background:#eaf0e4;border-left:3px solid #839e70;padding:15px}.stats{display:flex;gap:24px;flex-wrap:wrap;border-block:1px solid #c7d2bf;padding:15px 0}.stats strong{font-size:24px}.hint{background:#f4ebdd;padding:12px;border:1px solid #ddc6a4}.meta{color:#6b7c62;font-size:12px}details{border:1px solid #d0d9c9;padding:12px;margin:15px 0}.print-help{background:#eff2ea;padding:12px}@media print{body{margin:0;max-width:none}.print-help,details{display:none}article{break-inside:auto}h2,h3{break-after:avoid}.callout{break-inside:avoid}}</style><div class="kicker">SCOPECHECK / AUTHORIZED DEFENSIVE OBSERVATIONS</div><h1>Evidence report</h1>'
    ]
    parts.append(
        '<p class="meta">'
        + esc(report["created_utc"])
        + " | v"
        + esc(report["version"])
        + "</p>"
    )
    parts.append(
        '<div class="print-help">For a PDF: Ctrl+P (Mac: Cmd+P), then Save as PDF. All open ports are included below, independent of the app filter.</div>'
    )
    parts.append(
        text("Target", scope["target"])
        + text("Selected IP", scope["selected_address"])
        + text("Run status", report["status"])
    )
    parts.append(
        '<div class="stats">'
        + "".join(
            "<span><strong>" + esc(summary[k]) + "</strong> " + esc(k) + "</span>"
            for k in ["open", "closed", "timeout", "error"]
        )
        + "</div>"
    )
    parts.append(
        "<p>"
        + esc(coverage["completed"])
        + " / "
        + esc(coverage["requested"])
        + " ports observed; "
        + esc(coverage["unscanned"])
        + " unscanned; "
        + esc(coverage["open_checks_pending"])
        + " open-port checks pending.</p>"
    )
    parts.append(
        '<div class="callout"><b>Not a confirmed vulnerability assessment.</b> Open ports, missing headers and banner-version matches require owner review. Cancelled runs are incomplete. A clean report does not prove security.</div>'
    )
    for row in report["results"]:
        if row["state"] != "open":
            continue
        parts.append("<article><h2>" + esc(row["port"]) + " / TCP / open</h2>")
        service = row.get("service", {})
        parts.append(
            text("Service", service.get("name", "not checked"))
            + text("Basis", service.get("basis", "TCP connection observation"))
        )
        if row.get("check_note"):
            parts.append(text("Check coverage", row["check_note"]))
        h = row.get("http")
        if h:
            parts.append(
                "<h3>HTTP configuration</h3>"
                + text("Result", h.get("response_status", h["status"]))
            )
            if h.get("server_header"):
                parts.append(text("Unverified Server header", h["server_header"]))
            if h.get("missing_headers"):
                parts.append(
                    "<p><b>Missing headers / review items</b></p><ul>"
                    + "".join("<li>" + esc(v) + "</li>" for v in h["missing_headers"])
                    + "</ul>"
                )
            for k, v in h.get("security_headers", {}).items():
                if v:
                    parts.append(text(k, v))
            if "frame_protection_header_present" in h:
                parts.append(
                    text(
                        "Frame protection header present",
                        h["frame_protection_header_present"],
                    )
                )
            for c in h.get("cookies", []):
                parts.append(
                    text(
                        "Cookie " + c["name"],
                        f"Secure={c['secure']}, HttpOnly={c['httponly']}, SameSite={c['samesite'] or 'not set'} (value omitted)",
                    )
                )
            for hint in h.get("version_hints", []):
                parts.append(
                    '<div class="hint"><b>Possible version match, not confirmed</b>'
                    + text("Advisories", ", ".join(hint["advisories"]))
                    + text(
                        "Reported product",
                        hint["product"] + " " + hint["reported_version"],
                    )
                    + "<p>"
                    + esc(hint["note"])
                    + "</p>"
                    + text("Official source", hint["source"])
                    + "</div>"
                )
            parts.append('<p class="meta">' + esc(h.get("note", "")) + "</p>")
        t = row.get("tls")
        if t:
            parts.append("<h3>TLS / certificate</h3>" + text("Result", t["status"]))
            for k in [
                "protocol",
                "cipher",
                "subject",
                "issuer",
                "expires",
                "days_remaining",
                "expiry_review",
                "negotiated_legacy_protocol",
                "reason",
                "error",
            ]:
                if k in t:
                    parts.append(text(k, t[k]))
            parts.append('<p class="meta">' + esc(t.get("note", "")) + "</p>")
        if row.get("banner"):
            parts.append(
                "<h3>Passive greeting</h3>"
                + text(
                    "Unverified text",
                    row["banner"].get("text", row["banner"]["status"]),
                )
            )
        parts.append(
            "<details><summary>Raw observation JSON</summary><pre>"
            + esc(json.dumps(row, indent=2, ensure_ascii=True))
            + "</pre></details></article>"
        )
    parts.append("<h2>Scope and method</h2>")
    for k, v in report["configuration"].items():
        parts.append(text(k, v))
    parts.append(
        text("Resolved addresses", ", ".join(scope["resolved_addresses"]))
        + text("Own-machine target", scope.get("own_machine", False))
    )
    parts.append(
        "<h3>Limitations</h3><ul>"
        + "".join("<li>" + esc(x) + "</li>" for x in report["limits"])
        + '</ul><p class="meta">JSON export includes all observed port states. This HTML details every open port. Reports can contain private data; share only within permission and use the owner\'s responsible-disclosure channel.</p></html>'
    )
    return "".join(parts)


def render_csv(report):
    """One row per probed port; stdlib csv quoting handles any target text."""
    import csv, io

    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(
        [
            "target",
            "created_utc",
            "port",
            "state",
            "connect_ms",
            "service",
            "service_basis",
            "verified_protocol",
            "http_status",
            "http_response_status",
            "server_header_unverified",
            "missing_headers",
            "checks_run",
            "detail",
        ]
    )
    for row in report["results"]:
        service = row.get("service") or {}
        http = row.get("http") or {}
        detail = row.get("check_note") or row.get("note") or row.get("error") or ""
        w.writerow(
            [
                report["scope"]["target"],
                report["created_utc"],
                row["port"],
                row["state"],
                row.get("connect_ms", ""),
                service.get("name", ""),
                service.get("basis", ""),
                service.get("verified_protocol", ""),
                http.get("status", ""),
                http.get("response_status", ""),
                http.get("server_header", ""),
                "; ".join(http.get("missing_headers", [])),
                "; ".join(row.get("checks_run", [])),
                detail,
            ]
        )
    return out.getvalue()


def render_md(report):
    """Markdown report for pasting into issues/docs. Every remote string is
    flattened to one line and pipe-escaped so table cells cannot break out."""
    def esc(x):
        s = str(x)
        return (
            s.replace("\\", "\\\\")
            .replace("|", "\\|")
            .replace("\r", " ")
            .replace("\n", " ")
        )

    scope = report["scope"]
    summary = report["summary"]
    coverage = report["coverage"]
    lines = [
        "# ScopeCheck evidence report",
        "",
        "_" + esc(report["created_utc"]) + " · v" + esc(report["version"]) + "_",
        "",
        "- **Target:** " + esc(scope["target"]),
        "- **Selected IP:** " + esc(scope["selected_address"]),
        "- **Run status:** " + esc(report["status"]),
        "",
        "**Ports:** "
        + " · ".join(
            esc(summary[k]) + " " + k for k in ["open", "closed", "timeout", "error"]
        ),
        "",
        "**Coverage:** "
        + esc(coverage["completed"])
        + " / "
        + esc(coverage["requested"])
        + " ports observed; "
        + esc(coverage["unscanned"])
        + " unscanned; "
        + esc(coverage["open_checks_pending"])
        + " open-port checks pending.",
        "",
        "> **Not a confirmed vulnerability assessment.** Open ports, missing"
        " headers and banner-version matches require owner review. Cancelled"
        " runs are incomplete. A clean report does not prove security.",
        "",
        "## All probed ports",
        "",
        "| Port | State | Connect ms | Service | HTTP | Missing headers | Detail |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in report["results"]:
        service = row.get("service") or {}
        http = row.get("http") or {}
        detail = row.get("check_note") or row.get("note") or row.get("error") or ""
        lines.append(
            "| "
            + " | ".join(
                [
                    esc(row["port"]),
                    esc(row["state"]),
                    esc(row.get("connect_ms", "")),
                    esc(service.get("name", "")),
                    esc(http.get("response_status", http.get("status", ""))),
                    esc("; ".join(http.get("missing_headers", []))),
                    esc(detail),
                ]
            )
            + " |"
        )
    open_rows = [r for r in report["results"] if r["state"] == "open"]
    if open_rows:
        lines += ["", "## Open port detail", ""]
    for row in open_rows:
        service = row.get("service", {})
        lines.append("### " + esc(row["port"]) + " / TCP / open")
        lines.append("")
        lines.append(
            "- **Service:** "
            + esc(service.get("name", "not checked"))
            + " — "
            + esc(service.get("basis", "TCP connection observation"))
        )
        if row.get("check_note"):
            lines.append("- **Check coverage:** " + esc(row["check_note"]))
        h = row.get("http")
        if h:
            lines.append(
                "- **HTTP result:** " + esc(h.get("response_status", h["status"]))
            )
            if h.get("server_header"):
                lines.append(
                    "- **Unverified Server header:** " + esc(h["server_header"])
                )
            for v in h.get("missing_headers", []):
                lines.append("- **Missing header / review item:** " + esc(v))
        t = row.get("tls")
        if t:
            lines.append("- **TLS result:** " + esc(t["status"]))
            if t.get("expires"):
                lines.append("- **Certificate expires:** " + esc(t["expires"]))
        if row.get("banner"):
            lines.append(
                "- **Unverified greeting text:** "
                + esc(row["banner"].get("text", row["banner"]["status"]))
            )
        lines.append("")
    lines += [
        "---",
        "",
        "_Markdown export includes all observed port states, like the JSON and"
        " CSV exports. Reports can contain private data; share only within"
        " permission and use the owner's responsible-disclosure channel._",
        "",
    ]
    return "\n".join(lines)
