"""ScopeCheck: bounded TCP and configuration observations for authorized systems."""

import argparse
from advisories import version_hints
import concurrent.futures
import datetime as dt
import html
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import threading
import time

VERSION = "0.2.0"
DEFAULT_PORTS = [22, 80, 443, 8000, 8080]
MAX_PORTS = 65535


def ports(value):
    from profiles import PRESETS

    if value in PRESETS:
        return sorted(PRESETS[value])
    result = set()
    for part in value.split(","):
        if not re.fullmatch(r"\d+(?:-\d+)?", part):
            raise ValueError(
                "Ports must be numbers or ranges, for example 22,80,443 or 8000-8005"
            )
        lo, hi = map(int, part.split("-")) if "-" in part else (int(part), int(part))
        if not 1 <= lo <= hi <= 65535 or hi - lo + 1 > MAX_PORTS:
            raise ValueError("Ports must be 1-65535, with at most 65535 ports total")
        result.update(range(lo, hi + 1))
        if len(result) > MAX_PORTS:
            raise ValueError("At most 65535 ports per run")
    return sorted(result)


def target_name(value):
    if not value or len(value) > 253 or any(c in value for c in "\r\n/@?#"):
        raise ValueError("Use one hostname or IP only, not a URL or network range")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        try:
            name = value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Invalid hostname") from exc
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", name):
            raise ValueError("Invalid hostname")
        if any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in name.split(".")
        ):
            raise ValueError("Invalid hostname")
        return name


def local_addresses():
    """Actual interface addresses only. DNS names/private ranges do not prove ownership."""
    found = {"127.0.0.1", "::1"}
    try:
        import psutil

        for values in psutil.net_if_addrs().values():
            for value in values:
                if value.family in (socket.AF_INET, socket.AF_INET6):
                    try:
                        parsed = ipaddress.ip_address(value.address.split("%", 1)[0])
                        if (
                            not parsed.is_unspecified
                            and not parsed.is_multicast
                            and not (parsed.version == 6 and parsed.is_link_local)
                        ):
                            found.add(str(parsed))
                    except ValueError:
                        pass
    except (ImportError, OSError):
        pass
    return found


def resolve_plan(target, authorized=False, scope=()):
    target = target_name(target)
    answers = sorted(
        {
            item[4][0]
            for item in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        },
        key=lambda s: (ipaddress.ip_address(s).version, s),
    )
    if not answers:
        raise ValueError("No target address resolved")
    own = local_addresses()
    networks = [ipaddress.ip_network(x, strict=False) for x in scope]
    for raw in answers:
        address = ipaddress.ip_address(raw)
        if (
            address.is_unspecified
            or address.is_multicast
            or (address.is_link_local and raw not in own)
        ):
            raise ValueError(
                "Unspecified, multicast and link-local targets are not supported"
            )
        if raw not in own and not address.is_loopback:
            if not authorized:
                raise ValueError(
                    "External devices require ownership/written-permission confirmation"
                )
            if not networks or not any(address in net for net in networks):
                raise ValueError(
                    "Every non-owned DNS address must be inside the explicitly authorized scope"
                )
    return {
        "target": target,
        "resolved_addresses": answers,
        "selected_address": answers[0],
        "scope": list(scope),
        "authorization_confirmed": bool(authorized),
        "own_machine": all(
            x in own or ipaddress.ip_address(x).is_loopback for x in answers
        ),
        "loopback_only": all(ipaddress.ip_address(x).is_loopback for x in answers),
    }


class RateGate:
    def __init__(self, rate):
        self.interval = 1 / rate
        self.lock = threading.Lock()
        self.next_start = 0

    def wait(self):
        with self.lock:
            delay = max(0, self.next_start - time.monotonic())
            if delay:
                time.sleep(delay)
            self.next_start = time.monotonic() + self.interval


def tcp_probe(address, port, timeout, gate):
    gate.wait()
    started = time.monotonic()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return {
                "port": port,
                "state": "open",
                "connect_ms": round((time.monotonic() - started) * 1000, 1),
            }
    except ConnectionRefusedError:
        return {"port": port, "state": "closed"}
    except (TimeoutError, socket.timeout):
        return {
            "port": port,
            "state": "timeout",
            "note": "No response within the configured timeout; not proof of a firewall",
        }
    except OSError as exc:
        return {
            "port": port,
            "state": "error",
            "error": exc.__class__.__name__,
            "errno": exc.errno,
        }


def tls_observation(address, hostname, port, timeout, gate):
    gate.wait()
    try:
        with socket.create_connection((address, port), timeout=timeout) as raw:
            with ssl.create_default_context().wrap_socket(
                raw, server_hostname=hostname
            ) as conn:
                cert = conn.getpeercert()
                expires = cert.get("notAfter")
                days = (
                    int((ssl.cert_time_to_seconds(expires) - time.time()) // 86400)
                    if expires
                    else None
                )
                return {
                    "status": "verified",
                    "protocol": conn.version(),
                    "cipher": conn.cipher()[0],
                    "expires": expires,
                    "days_remaining": days,
                    "expiry_review": (
                        "expired"
                        if days is not None and days < 0
                        else (
                            "expires_within_30_days"
                            if days is not None and days < 30
                            else "not_near_expiry"
                        )
                    ),
                    "subject": str(cert.get("subject", ())),
                    "issuer": str(cert.get("issuer", ())),
                    "negotiated_legacy_protocol": conn.version()
                    in {"TLSv1", "TLSv1.1"},
                    "note": "One negotiated connection only; not a complete TLS protocol or cipher audit",
                }
    except ssl.SSLCertVerificationError as exc:
        return {
            "status": "certificate_not_verified",
            "reason": getattr(exc, "verify_message", str(exc)),
            "note": "May reflect a private CA or local trust store, not necessarily an exploitable vulnerability",
        }
    except (OSError, ssl.SSLError) as exc:
        return {
            "status": "check_failed",
            "error": exc.__class__.__name__,
            "note": "No insecure fallback attempted; service may not speak TLS",
        }


def http_observation(address, hostname, port, timeout, gate, tls=False):
    gate.wait()
    conn = None
    try:
        conn = socket.create_connection((address, port), timeout=timeout)
        if tls:
            conn = ssl.create_default_context().wrap_socket(
                conn, server_hostname=hostname
            )
        host = ("[" + hostname + "]") if ":" in hostname else hostname
        request = f"HEAD / HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: ScopeCheck/{VERSION}\r\nConnection: close\r\n\r\n"
        conn.sendall(request.encode("ascii"))
        data = b""
        deadline = time.monotonic() + timeout
        while b"\r\n\r\n" not in data and len(data) < 16384:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP header deadline exceeded")
            conn.settimeout(remaining)
            chunk = conn.recv(min(4096, 16384 - len(data)))
            if not chunk:
                break
            data += chunk
        if b"\r\n\r\n" not in data:
            return {
                "status": "incomplete_response",
                "note": "Headers absent or exceeded 16 KiB; not assessed",
            }
        lines = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1").split("\r\n")
        if not re.fullmatch(r"HTTP/1\.[01] \d{3}(?: .*)?", lines[0]):
            return {
                "status": "not_http1",
                "note": "Only HTTP/1.x HEAD responses supported",
            }
        headers = {}
        cookies = []
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.lower().strip()] = value.strip()
                if key.lower().strip() == "set-cookie":
                    parts = [x.strip() for x in value.split(";")]
                    attrs = {
                        x.split("=", 1)[0].lower(): (
                            x.split("=", 1)[1] if "=" in x else True
                        )
                        for x in parts[1:]
                    }
                    cookies.append(
                        {
                            "name": parts[0].split("=", 1)[0],
                            "secure": bool(attrs.get("secure")),
                            "httponly": bool(attrs.get("httponly")),
                            "samesite": attrs.get("samesite"),
                            "note": "Cookie values omitted; flags are observations, not exploitability proof",
                        }
                    )
        wanted = [
            "content-security-policy",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "cross-origin-opener-policy",
        ]
        if tls:
            wanted.append("strict-transport-security")
        observed = {key: headers.get(key) for key in wanted}
        frame_policy = (
            "content-security-policy" in headers
            and "frame-ancestors" in headers["content-security-policy"].lower()
        )
        return {
            "status": "observed",
            "response_status": lines[0],
            "transport": "HTTPS" if tls else "HTTP",
            "cookies": cookies,
            "server_header": headers.get("server"),
            "version_hints": version_hints(headers.get("server")),
            "security_headers": observed,
            "missing_headers": [k for k, v in observed.items() if not v],
            "frame_protection_header_present": bool(
                headers.get("x-frame-options") or frame_policy
            ),
            "note": "HEAD / only, no redirect following. Missing headers are review items, not confirmed vulnerabilities. Header presence does not validate its policy.",
        }
    except (OSError, ssl.SSLError) as exc:
        return {
            "status": "check_failed",
            "error": exc.__class__.__name__,
            "note": "No insecure fallback or redirect following",
        }
    finally:
        if conn:
            conn.close()


def passive_banner(address, port, timeout, gate):
    gate.wait()
    try:
        with socket.create_connection((address, port), timeout=timeout) as conn:
            value = conn.recv(256)
        # Only print visible ASCII. Never interpret terminal escapes or HTML.
        text = "".join(chr(x) if 32 <= x < 127 else "." for x in value)
        return {
            "status": "observed" if value else "empty",
            "text": text,
            "note": "Unverified service text, not a trusted version or CVE finding",
        }
    except (OSError, socket.timeout) as exc:
        return {"status": "not_observed", "error": exc.__class__.__name__}


def scan(
    plan,
    port_list,
    timeout=1,
    workers=4,
    rate=5,
    http_ports=(),
    tls_ports=(),
    banner_ports=(),
):
    from engine import execute

    return execute(
        plan,
        port_list,
        timeout,
        workers,
        rate,
        True,
        http_ports,
        tls_ports,
        banner_ports,
    )


def write_report(report, path):
    path = Path(path)
    # Exclusive create avoids clobbering a prior report or following a file symlink.
    with path.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=True)
        handle.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?", default="127.0.0.1")
    parser.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)))
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you own the target or have written permission for the exact scope",
    )
    parser.add_argument(
        "--scope",
        action="append",
        default=[],
        help="Approved numeric IP or CIDR, repeatable; required for every non-loopback address",
    )
    parser.add_argument("--timeout", type=float, default=1)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--rate", type=float, default=5)
    parser.add_argument("--http-ports", default="")
    parser.add_argument("--tls-ports", default="")
    parser.add_argument("--banner-ports", default="")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Resolve and validate scope, but make no scan connections",
    )
    args = parser.parse_args(argv)
    try:
        port_list = ports(args.ports)
        plan = resolve_plan(args.target, args.authorized, args.scope)
        options = {
            k: ports(getattr(args, k)) if getattr(args, k) else []
            for k in ["http_ports", "tls_ports", "banner_ports"]
        }
        if args.plan_only:
            print(
                json.dumps(
                    {
                        "plan": plan,
                        "ports": port_list,
                        "note": "No scan connections made; DNS resolution may have occurred",
                    },
                    indent=2,
                )
            )
            return 0
        report = scan(plan, port_list, args.timeout, args.workers, args.rate, **options)
        if args.output:
            write_report(report, args.output)
        print(json.dumps(report, indent=2, ensure_ascii=True))
        return 0
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Stopped: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
