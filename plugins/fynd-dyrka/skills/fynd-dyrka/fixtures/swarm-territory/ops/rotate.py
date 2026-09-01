"""Service key rotation. Triggered on a schedule."""
import pickle
import base64
import os

STATE_FILE = "/var/lib/reports/rotation_state.b64"


def load_state():
    """Reads the rotation state saved by the previous run."""
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE) as f:
        return pickle.loads(base64.b64decode(f.read()))


def save_state(state):
    with open(STATE_FILE, "w") as f:
        f.write(base64.b64encode(pickle.dumps(state)).decode())
