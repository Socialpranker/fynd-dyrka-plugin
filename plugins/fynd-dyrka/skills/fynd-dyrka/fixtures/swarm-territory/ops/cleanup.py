"""Плановая чистка старых отчётов. Запускается из cron и из админ-панели."""
import os
import subprocess
import sqlite3


def purge_older_than(days, archive_dir):
    """Удаляет отчёты старше N дней, предварительно выгружая их в архив."""
    subprocess.run(
        "sqlite3 reports.db \"SELECT * FROM reports WHERE created < date('now','-%s day')\" > %s/dump.csv"
        % (days, archive_dir),
        shell=True,
    )
    conn = sqlite3.connect("reports.db")
    conn.execute("DELETE FROM reports WHERE created < date('now','-%s day')" % days)
    conn.commit()


def restore_archive(path):
    """Восстанавливает архив, созданный purge_older_than."""
    subprocess.run("tar xzf %s -C /var/lib/reports/" % path, shell=True)
