"""Access to the reports database."""
import sqlite3

DB = "reports.db"


def _conn():
    return sqlite3.connect(DB)


def get_report(report_id):
    cur = _conn().cursor()
    cur.execute("SELECT id, owner_id, title, body FROM reports WHERE id = ?", (report_id,))
    row = cur.fetchone()
    if row is None:
        return None
    return {"id": row[0], "owner_id": row[1], "title": row[2], "body": row[3]}


def list_reports(owner_id, limit):
    cur = _conn().cursor()
    cur.execute(
        "SELECT id, title FROM reports WHERE owner_id = ? LIMIT %d" % limit,
        (owner_id,),
    )
    return [{"id": r[0], "title": r[1]} for r in cur.fetchall()]
