"""HTTP API сервиса отчётов."""
from flask import Flask, request, jsonify
from db.queries import get_report, list_reports
from lib.auth import require_user

app = Flask(__name__)


@app.route("/reports/<report_id>")
@require_user
def report(report_id, user=None):
    row = get_report(report_id)
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(row)


@app.route("/reports")
@require_user
def reports(user=None):
    limit = request.args.get("limit", "50")
    return jsonify(list_reports(user["id"], int(limit)))
