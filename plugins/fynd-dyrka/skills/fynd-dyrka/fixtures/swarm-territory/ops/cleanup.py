"""Scheduled cleanup of old reports. Run from cron and from the admin panel."""
import os
import subprocess
import sqlite3


def purge_older_than(days, archive_dir):
    """Deletes reports older than N days, archiving them first."""
    subprocess.run(
        "sqlite3 reports.db \"SELECT * FROM reports WHERE created < date('now','-%s day')\" > %s/dump.csv"
        % (days, archive_dir),
        shell=True,
    )
    conn = sqlite3.connect("reports.db")
    conn.execute("DELETE FROM reports WHERE created < date('now','-%s day')" % days)
    conn.commit()


def restore_archive(path):
    """Restores an archive created by purge_older_than."""
    subprocess.run("tar xzf %s -C /var/lib/reports/" % path, shell=True)
