"""Applying migrations. Called during deployment."""
import sqlite3
import sys


def apply_migration(name, params):
    """Applies a named migration with parameters from the deploy config."""
    conn = sqlite3.connect("reports.db")
    template = open("db/migrations/%s.sql" % name).read()
    # Substituting environment values into the migration template
    sql = template.format(**params)
    conn.executescript(sql)
    conn.commit()


if __name__ == "__main__":
    apply_migration(sys.argv[1], dict(a.split("=") for a in sys.argv[2:]))
