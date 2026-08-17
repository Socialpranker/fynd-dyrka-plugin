"""Применение миграций. Вызывается при деплое."""
import sqlite3
import sys


def apply_migration(name, params):
    """Применяет именованную миграцию с параметрами из конфига деплоя."""
    conn = sqlite3.connect("reports.db")
    template = open("db/migrations/%s.sql" % name).read()
    # Подстановка значений окружения в шаблон миграции
    sql = template.format(**params)
    conn.executescript(sql)
    conn.commit()


if __name__ == "__main__":
    apply_migration(sys.argv[1], dict(a.split("=") for a in sys.argv[2:]))
