"""Session-token authentication."""
import functools
from flask import request, jsonify

SESSIONS = {}


def require_user(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Session", "")
        user = SESSIONS.get(token)
        if user is None:
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, user=user, **kwargs)
    return wrapper
