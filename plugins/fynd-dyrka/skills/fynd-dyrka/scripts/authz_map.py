#!/usr/bin/env python3
"""
authz_map — картограф attack surface для аудита авторизации.

НЕ сканер уязвимостей. Строит инвентарь точек входа (роуты, Server Actions,
API-хендлеры) и по каждой отвечает на ОДИН вопрос: виден ли рядом вызов
аутентификации/авторизации? Выход — таблица, которая служит ВХОДОМ в ручной
разбор (Шаг 3 скилла), а не заменой ему: скрипт не решает, что дыра, он
подсвечивает места, где auth не виден и которые стоит прочитать глазами.

Почему это ценно: на большом репо ручная инвентаризация Шага 2 съедает контекст
до начала анализа. Скрипт механизирует её — грепает точки входа и группирует по
«auth виден / не виден / неясно», чтобы разбор сразу шёл по подсвеченным.

Три исхода по каждому эндпоинту:
  yes     — вызов auth найден в теле хендлера;
  unclear — auth-механизм есть в модуле (импорт/middleware), но не видно, что он
            применён именно к этому хендлеру → прочитать глазами;
  NO      — ни в теле, ни в модуле auth не найдено → приоритет для разбора.

Честность про ложные негативы: auth может жить в middleware (Next.js
middleware.ts), в декораторе, в общей обёртке. Поэтому «NO» означает «не виден
здесь», а не «его точно нет». Скрипт для этого и нужен — сузить, что читать.

Usage:
  authz_map.py --target .            # текстовая таблица
  authz_map.py --target . --json     # JSON для machine-обработки
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

# Сигнатуры вызова auth/authz. Намеренно широкие — лучше пометить «unclear»,
# чем пропустить защищённый эндпоинт как «NO».
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
    r"@jwt_required",  # python-декораторы
    r"clerkClient",
    r"auth\.protect",
    r"withApiAuth",
    # Заголовочная / секретная auth машинных вызовов (internal / cron / webhook).
    # Без них картограф ложно метил защищённые internal-роуты как NO: реальный
    # инцидент на 10_FYND_DYRKA — scan-update с x-internal-token + timingSafeEqual
    # уходил в NO, потому что «сессионных» сигнатур в нём нет.
    r"timingSafeEqual",  # постоянное сравнение секрета — почти всегда auth
    r"compare_digest",  # python-аналог
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

# Admin/чувствительность по имени эндпоинта — для приоритизации в выводе.
_SENSITIVE_RE = re.compile(
    r"/(admin|manage|internal|delete|remove|billing|payment|pay|credit|"
    r"role|permission|user|account|settings|config)\b",
    re.I,
)

# HTTP-методы Next.js route handler.
_NEXT_HANDLER_RE = re.compile(
    r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b"
)
# Express/Fastify/Koa-роуты.
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
    """Из пути файла Next.js App Router собрать URL-подобный маршрут.

    app/api/admin/route.ts -> /api/admin ; группы (marketing) и приватные
    _folders в URL не входят — как в Next.js.
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


# Грубо убрать // и /* */ комментарии перед поиском auth-сигнатур. Без этого
# комментарий вида «намеренно без auth()» ложно матчит картограф — инцидент:
# фикс rate-limit на demo/route.ts добавил именно такой комментарий и сам себя
# обманул (все NO пропали, включая настоящие). Грубость приемлема: это фильтр
# ПЕРЕД regex-поиском сигнатуры, не парсер языка — ложноположительный "//"
# внутри строкового литера (редкость в auth-related коде) на исход не влияет,
# а не почистить комментарии хуже: там живут false positives каждый день.
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
    """Грубо вырезать тело функции от start_idx по балансу фигурных скобок.
    Без парсера — достаточно, чтобы отличить «auth в этом хендлере» от «auth
    где-то в файле»."""
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

        # 1) Next.js App Router: route.ts с export-хендлерами
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

        # 2) Server Actions: export async function в файле с "use server"
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

    # дедуп по (endpoint, файл)
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
