#!/usr/bin/env python3
"""
authz_map — an attack-surface cartographer for authorisation audits.

NOT a vulnerability scanner. It builds an inventory of entry points (routes,
Server Actions, API handlers) and answers ONE question about each: is an
authentication or authorisation call visible nearby? The output is a table that
serves as the ENTRY POINT into manual review (Step 3 of the skill), not a
replacement for it: the script does not decide what is a hole, it highlights
places where auth is not visible and that are worth reading by eye.

Why this is valuable: on a large repository the manual Step 2 inventory eats the
context before analysis begins. The script mechanises it — it greps entry points
and groups them by "auth visible / not visible / unclear", so the review starts
from the highlighted ones.

Three outcomes per endpoint:
  yes     — an auth call was found in the handler body;
  unclear — an auth mechanism exists in the module (import/middleware) but it is
            not visibly applied to this handler -> read it by eye;
  NO      — no auth found in the body or the module -> priority for review.

Honesty about false negatives: auth may live in middleware (Next.js
middleware.ts), in a decorator, or in a shared wrapper. So "NO" means "not
visible here", not "definitely absent". Narrowing what to read is the point.

Usage:
  authz_map.py --target .            # text table
  authz_map.py --target . --json     # JSON for machine processing
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

VENDOR_DIRS = {
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".git",
    "dist",
    "build",
    ".next",
    ".cache",
    "vendor",
    "site-packages",
    ".tox",
    "coverage",
}

# Auth/authz call signatures. Deliberately broad — better to mark something
# "unclear" than to miss a protected endpoint as "NO".
AUTH_SIGNATURES = [
    r"\bauth\s*\(",  # auth() — next-auth v5
    r"getServerSession",  # next-auth v4
    r"getSession",
    r"requireAuth",
    r"requireUser",
    r"requireAdmin",
    r"requireRole",
    r"ensureAuth",
    r"isAuthenticated",
    r"checkAuth",
    r"currentUser",
    r"getCurrentUser",
    r"getUser\b",
    r"verifyToken",
    r"verifyJwt",
    r"verify_jwt",
    r"verifySession",
    r"\breq\.user\b",
    r"\bctx\.session\b",
    r"\bsession\??\.user\b",
    r"@login_required",
    r"@requires_auth",
    r"@jwt_required",  # Python decorators
    r"clerkClient",
    r"auth\.protect",
    r"withApiAuth",
    # Header/secret auth for machine callers (internal / cron / webhook).
    # Without these the cartographer falsely marked protected internal routes as
    # NO: a real incident had a scan-update route with x-internal-token plus
    # timingSafeEqual land in NO, because it carries no session-style signature.
    r"timingSafeEqual",  # constant-time secret comparison — almost always auth
    r"compare_digest",  # the Python equivalent
    r"x-internal-token",
    r"x-internal",
    r"x-api-key",
    r"x-webhook",
    r"x-signature",
    r"x-hub-signature",
    r"x-telegram-bot-api-secret-token",
    r"\bauthorization\b",
    r"Bearer\s",
    r"getToken\b",
    r"INTERNAL_TOKEN",
    r"INTERNAL_API_SECRET",
    r"CRON_SECRET",
    r"WEBHOOK_SECRET",
    r"API_SECRET",
    r"SERVICE_TOKEN",
    r"SHARED_SECRET",
    r"verifyHmac",
    r"verifySignature",
    r"validateSignature",
    r"verifyWebhook",
]
_AUTH_RE = re.compile("|".join(AUTH_SIGNATURES), re.IGNORECASE)

# Admin/sensitivity by endpoint name — used to prioritise the output.
_SENSITIVE_RE = re.compile(
    r"/(admin|manage|internal|delete|remove|billing|payment|pay|credit|"
    r"role|permission|user|account|settings|config)\b",
    re.I,
)

# Next.js route handler HTTP methods.
_NEXT_HANDLER_RE = re.compile(
    r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b"
)
# Express/Fastify/Koa routes.
_EXPRESS_RE = re.compile(
    r"\b(?:app|router|server|fastify)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*"
    r"[`'\"]([^`'\"]+)[`'\"]"
)


def _walk_files(target: str):
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in VENDOR_DIRS]
        for fn in files:
            if fn.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".py")):
                yield os.path.join(root, fn)


def _route_path_from_next_file(path: str, target: str) -> str:
    """Build a URL-like route from a Next.js App Router file path.

    app/api/admin/route.ts -> /api/admin ; groups (marketing) and private
    _folders are excluded from the URL, as in Next.js.
    """
    rel = os.path.relpath(path, target)
    parts = rel.split(os.sep)
    if parts and parts[0] in ("src",):
        parts = parts[1:]
    if parts and parts[0] == "app":
        parts = parts[1:]
    parts = [p for p in parts if not (p.startswith("(") and p.endswith(")"))]
    parts = [p for p in parts if p not in ("route.ts", "route.tsx", "route.js")]
    return "/" + "/".join(parts) if parts else "/"


# Crudely strip // and /* */ comments before searching for auth signatures.
# Without this a comment such as "deliberately without auth()" falsely matches —
# a real incident: a rate-limit fix on demo/route.ts added exactly such a comment
# and fooled the cartographer (every NO disappeared, including the real ones).
# The crudeness is acceptable: this is a filter BEFORE the signature regex, not a
# language parser — a false "//" inside a string literal (rare in auth-related
# code) does not change the outcome, while not stripping comments is worse,
# because false positives live there every day.
_LINE_COMMENT_RE = re.compile(r"//.*$", re.MULTILINE)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_PY_COMMENT_RE = re.compile(r"#.*$", re.MULTILINE)


def _strip_comments_for_auth_search(text: str) -> str:
    text = _BLOCK_COMMENT_RE.sub(" ", text)
    text = _LINE_COMMENT_RE.sub(" ", text)
    text = _PY_COMMENT_RE.sub(" ", text)
    return text


def _has_auth_in(text: str) -> bool:
    return bool(_AUTH_RE.search(_strip_comments_for_auth_search(text)))


def _slice_function_body(text: str, start_idx: int) -> str:
    """Crudely cut out a function body from start_idx by brace balance.
    No parser needed — enough to tell "auth in this handler" from "auth somewhere
    in the file"."""
    brace = text.find("{", start_idx)
    if brace == -1:
        return text[start_idx : start_idx + 400]
    depth = 0
    for i in range(brace, min(len(text), brace + 8000)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace : i + 1]
    return text[brace : brace + 8000]


def analyze(target: str) -> list[dict]:
    rows: list[dict] = []
    for path in _walk_files(target):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        module_has_auth = _has_auth_in(text)
        is_server_action = '"use server"' in text or "'use server'" in text
        base = os.path.basename(path)

        # 1) Next.js App Router: route.ts with exported handlers
        if base.startswith("route.") and base.endswith((".ts", ".tsx", ".js")):
            route = _route_path_from_next_file(path, target)
            for m in _NEXT_HANDLER_RE.finditer(text):
                method = m.group(1)
                body = _slice_function_body(text, m.start())
                rows.append(
                    _row(
                        f"{method} {route}",
                        path,
                        text,
                        body,
                        module_has_auth,
                        kind="next-route",
                    )
                )

        # 2) Server Actions: export async function in a file with "use server"
        if is_server_action:
            for m in re.finditer(
                r"export\s+(?:async\s+)?function\s+([A-Za-z0-9_]+)", text
            ):
                name = m.group(1)
                body = _slice_function_body(text, m.start())
                rows.append(
                    _row(
                        f"action {name}()",
                        path,
                        text,
                        body,
                        module_has_auth,
                        kind="server-action",
                    )
                )

        # 3) pages/api/*
        if (
            f"{os.sep}pages{os.sep}api{os.sep}" in path
            or f"{os.sep}api{os.sep}" in path
        ):
            if base not in ("route.ts", "route.tsx", "route.js") and re.search(
                r"export\s+default\s+(?:async\s+)?function", text
            ):
                m = re.search(r"export\s+default\s+(?:async\s+)?function", text)
                body = _slice_function_body(text, m.start()) if m else text
                route = _route_path_from_next_file(path, target)
                rows.append(
                    _row(
                        f"api {route}",
                        path,
                        text,
                        body,
                        module_has_auth,
                        kind="pages-api",
                    )
                )

        # 4) Express/Fastify/Koa
        for m in _EXPRESS_RE.finditer(text):
            method, route = m.group(1).upper(), m.group(2)
            body = _slice_function_body(text, m.start())
            rows.append(
                _row(
                    f"{method} {route}",
                    path,
                    text,
                    body,
                    module_has_auth,
                    kind="express",
                )
            )

    # deduplicate by (endpoint, file)
    seen = set()
    uniq = []
    for r in rows:
        k = (r["endpoint"], r["file"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r)
    return uniq


def _row(endpoint, path, text, body, module_has_auth, kind) -> dict:
    in_body = _has_auth_in(body)
    if in_body:
        verdict = "yes"
    elif module_has_auth:
        verdict = "unclear"
    else:
        verdict = "NO"
    return {
        "endpoint": endpoint,
        "file": path,
        "kind": kind,
        "auth": verdict,
        "sensitive": bool(_SENSITIVE_RE.search(endpoint)),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="AuthZ attack-surface inventory")
    ap.add_argument("--target", default=".")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    target = os.path.abspath(args.target)
    rows = analyze(target)

    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0

    if not rows:
        print("No entry points found (route.ts / Server Actions / api / express).")
        print("If this is not a web service, use the manual Step 2 inventory.")
        return 0

    order = {"NO": 0, "unclear": 1, "yes": 2}
    rows.sort(key=lambda r: (order[r["auth"]], not r["sensitive"], r["endpoint"]))
    no = sum(1 for r in rows if r["auth"] == "NO")
    unclear = sum(1 for r in rows if r["auth"] == "unclear")
    yes = sum(1 for r in rows if r["auth"] == "yes")

    print(f"# AuthZ attack surface — {len(rows)} entry points")
    print(f"# auth visible: {yes}   unclear: {unclear}   NOT visible: {no}")
    print(f"# {'LOOK HERE FIRST: NO + sensitive' if no else 'auth visible everywhere'}")
    print()
    print(f"{'auth':8} {'sens':5} {'endpoint':40} file")
    print("-" * 90)
    for r in rows:
        rel = os.path.relpath(r["file"], target)
        mark = "!" if r["sensitive"] else " "
        print(f"{r['auth']:8} {mark:^5} {r['endpoint'][:40]:40} {rel}")
    print()
    print("How to read this: auth=NO means auth is visible neither in the handler")
    print("nor in the module -> read these first. unclear means the module has auth")
    print("but it is not visibly applied to this handler (it may be in middleware)")
    print("-> check by eye. This is a map for Step 3, not a verdict: the script does")
    print("not know the business logic.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
