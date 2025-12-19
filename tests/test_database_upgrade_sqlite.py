# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import pytest
import re
import sqlite3
import subprocess
from pathlib import Path
from database import Database
from logtool import LogTool
from pyhss_config import config

top_dir = Path(Path(__file__) / "../..").resolve()
test_db = os.path.join(top_dir, "tests/.pyhss_test_database_upgrade.db")


def sqlite_dump_table_with_sorted_columns(lines):
    assert len(lines) > 2
    assert lines[-1] == ");"

    start = lines[0]
    end = lines[-1]

    columns_and_keys = " ".join(lines[1:-1])

    # Replace commas inside paranethesis first
    marker = "|"
    assert marker not in columns_and_keys
    for p in re.findall(r"\(.*?\)", columns_and_keys):
        columns_and_keys = columns_and_keys.replace(p, p.replace(",", marker))

    lines = columns_and_keys.split(",")
    columns = []
    keys = []

    for line in lines:
        line = line.replace(marker, ",").strip() + ","
        word = line.split(" ")[0]
        if word in ["UNIQUE", "FOREIGN", "PRIMARY"]:
            keys += [f"\t{line}"]
        else:
            columns += [f"\t{line}"]

    ret = [start]
    ret += sorted(columns)
    ret += keys
    ret[-1] = ret[-1].rstrip(",")
    ret += [end]
    return ret


def sqlite_dump(tmpdir):
    conn = sqlite3.connect(test_db)

    ret_sql = ""
    for cmd in conn.iterdump():
        lines = cmd.split("\n")

        if cmd.startswith("INSERT INTO "):
            continue

        if cmd.startswith("CREATE TABLE "):
            lines = sqlite_dump_table_with_sorted_columns(lines)

        for line in lines:
            ret_sql += f"{line.rstrip()}\n"

    conn.close()

    ret_path = os.path.join(tmpdir, "current_db.sql")
    with open(ret_path, "w") as f:
        f.write(ret_sql)

    return ret_sql, ret_path


def sqlite_dump_and_compare_with_latest(tmpdir):
    latest_path = os.path.join(top_dir, "tests/db_schema/latest.sql")
    with open(latest_path) as f:
        latest_sql = f.read()

    current_sql, current_path = sqlite_dump(tmpdir)

    if current_sql != latest_sql:
        subprocess.run(["git", "diff", "--no-index", "--color=always", latest_path, current_path])
        print()
        print("ERROR: The database schema has changed. Please add upgrade logic as described here:")
        print("https://github.com/nickvsnetworking/pyhss/blob/master/docs/databases.md")
        print()
        raise RuntimeError("sqlite_dump_and_compare_with_latest failed")


def sqlite_import(sql_file):
    if os.path.exists(test_db):
        os.unlink(test_db)

    conn = sqlite3.connect(test_db)
    with open(os.path.join(top_dir, "tests/db_schema", sql_file)) as f:
        sql_script = f.read()
    conn.executescript(sql_script)
    conn.close()


def test_sqlite_new_db(tmpdir, monkeypatch):
    if os.path.exists(test_db):
        os.unlink(test_db)

    monkeypatch.setitem(config["database"], "database", test_db)
    db = Database(LogTool(config), main_service=True)
    db.engine.dispose()

    sqlite_dump_and_compare_with_latest(tmpdir)


def test_sqlite_upgrade_from_1_0_1(tmpdir, monkeypatch):
    monkeypatch.setitem(config["database"], "database", test_db)
    sqlite_import("20240125_release_1.0.1.sql")

    db = Database(LogTool(config), main_service=True)
    db.engine.dispose()

    sqlite_dump_and_compare_with_latest(tmpdir)


def test_sqlite_unsupported_1_0_0(tmpdir, monkeypatch):
    monkeypatch.setitem(config["database"], "database", test_db)
    sqlite_import("20231009_release_1.0.0.sql")

    with pytest.raises(SystemExit) as e:
        Database(LogTool(config), main_service=True)
    assert e.value.code == 20
