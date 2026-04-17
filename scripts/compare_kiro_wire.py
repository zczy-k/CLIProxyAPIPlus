#!/usr/bin/env python3
"""Compare observed Kiro login wire dump against expected ghost-client shape.

Usage:
  python3 scripts/compare_kiro_wire.py network_dump.jsonl
"""

from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path


def b64_to_text(value: str | None) -> str:
    if not value:
        return ""
    try:
        return base64.b64decode(value).decode("utf-8", errors="replace")
    except Exception:
        return ""


def body_json(entry: dict) -> dict:
    text = b64_to_text(entry.get("request", {}).get("content_b64"))
    if not text:
        return {}
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def first(entries: list[dict], pred):
    for e in entries:
        if pred(e):
            return e
    return None


def status(pass_ok: bool) -> str:
    return "PASS" if pass_ok else "FAIL"


def row(name: str, expected: str, actual: str, ok: bool) -> str:
    return f"| {name} | {expected} | {actual} | {status(ok)} |"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python3 scripts/compare_kiro_wire.py <network_dump.jsonl>")
        return 2

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"file not found: {path}")
        return 2

    entries = [
        json.loads(line) for line in path.read_text().splitlines() if line.strip()
    ]

    c_getid = first(
        entries,
        lambda e: (
            e.get("request", {}).get("url")
            == "https://cognito-identity.us-east-1.amazonaws.com/"
            and e.get("request", {}).get("headers", {}).get("x-amz-target")
            == "AWSCognitoIdentityService.GetId"
        ),
    )
    c_creds = first(
        entries,
        lambda e: (
            e.get("request", {}).get("url")
            == "https://cognito-identity.us-east-1.amazonaws.com/"
            and e.get("request", {}).get("headers", {}).get("x-amz-target")
            == "AWSCognitoIdentityService.GetCredentialsForIdentity"
        ),
    )
    oauth = first(
        entries,
        lambda e: (
            e.get("request", {}).get("url")
            == "https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token"
        ),
    )
    telemetry_entries = [
        e
        for e in entries
        if e.get("request", {}).get("url")
        == "https://client-telemetry.us-east-1.amazonaws.com/metrics"
    ]
    telemetry = telemetry_entries[0] if telemetry_entries else None

    print("| Check | Expected | Actual | Result |")
    print("|---|---|---|---|")

    oauth_headers = (oauth or {}).get("request", {}).get("headers", {})
    oauth_body = body_json(oauth or {})

    checks = []
    checks.append(
        row(
            "OAuth endpoint",
            "https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token",
            (oauth or {}).get("request", {}).get("url", "<missing>"),
            oauth is not None,
        )
    )
    checks.append(
        row(
            "OAuth User-Agent",
            "Kiro-CLI",
            oauth_headers.get("user-agent", "<missing>"),
            oauth_headers.get("user-agent") == "Kiro-CLI",
        )
    )
    checks.append(
        row(
            "OAuth redirect_uri",
            "http://localhost:3128/oauth/callback?login_option=google",
            oauth_body.get("redirect_uri", "<missing>"),
            oauth_body.get("redirect_uri")
            == "http://localhost:3128/oauth/callback?login_option=google",
        )
    )
    checks.append(
        row(
            "PKCE verifier present",
            "non-empty code_verifier",
            "present" if oauth_body.get("code_verifier") else "missing",
            bool(oauth_body.get("code_verifier")),
        )
    )

    c_getid_headers = (c_getid or {}).get("request", {}).get("headers", {})
    c_getid_body = body_json(c_getid or {})
    checks.append(
        row(
            "Cognito GetId target",
            "AWSCognitoIdentityService.GetId",
            c_getid_headers.get("x-amz-target", "<missing>"),
            c_getid_headers.get("x-amz-target") == "AWSCognitoIdentityService.GetId",
        )
    )
    checks.append(
        row(
            "Cognito IdentityPoolId",
            "us-east-1:820fd6d1-95c0-4ca4-bffb-3f01d32da842",
            c_getid_body.get("IdentityPoolId", "<missing>"),
            c_getid_body.get("IdentityPoolId")
            == "us-east-1:820fd6d1-95c0-4ca4-bffb-3f01d32da842",
        )
    )

    c_creds_headers = (c_creds or {}).get("request", {}).get("headers", {})
    checks.append(
        row(
            "Cognito GetCredentials target",
            "AWSCognitoIdentityService.GetCredentialsForIdentity",
            c_creds_headers.get("x-amz-target", "<missing>"),
            c_creds_headers.get("x-amz-target")
            == "AWSCognitoIdentityService.GetCredentialsForIdentity",
        )
    )

    telemetry_headers = (telemetry or {}).get("request", {}).get("headers", {})
    auth_header = telemetry_headers.get("authorization", "")
    sig_ok = bool(
        re.search(
            r"^AWS4-HMAC-SHA256 Credential=[^/]+/\d{8}/us-east-1/execute-api/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token;x-amz-user-agent, Signature=[0-9a-f]{64}$",
            auth_header,
        )
    )
    checks.append(
        row(
            "Telemetry endpoint",
            "https://client-telemetry.us-east-1.amazonaws.com/metrics",
            (telemetry or {}).get("request", {}).get("url", "<missing>"),
            telemetry is not None,
        )
    )
    checks.append(
        row(
            "Telemetry SigV4",
            "execute-api us-east-1 signed",
            "valid" if sig_ok else "invalid",
            sig_ok,
        )
    )
    metric_names = []
    for t in telemetry_entries:
        t_body = body_json(t)
        md = t_body.get("MetricData")
        if isinstance(md, list):
            for item in md:
                if isinstance(item, dict) and isinstance(item.get("MetricName"), str):
                    metric_names.append(item["MetricName"])
    metric_name = ", ".join(metric_names) if metric_names else "<missing>"
    metric_ok = "codewhispererterminal_userLoggedIn" in metric_names
    checks.append(
        row(
            "Telemetry metric",
            "codewhispererterminal_userLoggedIn",
            metric_name,
            metric_ok,
        )
    )

    for c in checks:
        print(c)

    passed = sum(1 for c in checks if c.endswith("| PASS |"))
    total = len(checks)
    print(f"\nResult: {passed}/{total} checks PASS")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
