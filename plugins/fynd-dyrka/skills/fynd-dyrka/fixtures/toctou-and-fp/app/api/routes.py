"""Public HTTP API. Все внешние переходы проходят через lib.urlcheck."""
from flask import Flask, request, redirect, jsonify
import requests

from app.lib.urlcheck import validate_redirect, is_internal_host

app = Flask(__name__)


@app.route("/go")
def go():
    target = request.args.get("url", "")
    if not validate_redirect(target):
        return jsonify({"error": "blocked"}), 400
    return redirect(target)


@app.route("/fetch-preview")
def fetch_preview():
    target = request.args.get("url", "")
    if is_internal_host(target):
        return jsonify({"error": "internal host denied"}), 403
    resp = requests.get(target, timeout=5, allow_redirects=False)
    return jsonify({"status": resp.status_code, "len": len(resp.content)})


@app.route("/health")
def health():
    return jsonify({"ok": True})
