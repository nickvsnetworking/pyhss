# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import sqlite3
import os
import glob
import re
import pytest
from pathlib import Path
from database import Database
from logtool import LogTool
from pyhss_config import config

top_dir = Path(Path(__file__) / "../..").resolve()
test_db = os.path.join(top_dir, "tests/.pyhss_test_database_upgrade.db")


def create_table_with_sorted_columns(lines):
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


def dump_sql(tmpdir):
    conn = sqlite3.connect(test_db)

    ret_sql = ""
    for cmd in conn.iterdump():
        lines = cmd.split("\n")

        if cmd.startswith("INSERT INTO "):
            continue

        if cmd.startswith("CREATE TABLE "):
            lines = create_table_with_sorted_columns(lines)

        for line in lines:
            ret_sql += f"{line.rstrip()}\n"

    conn.close()

    ret_path = os.path.join(tmpdir, "current_db.sql")
    with open(ret_path, "w") as f:
        f.write(ret_sql)

    return ret_sql, ret_path


def compare_with_latest_sql(tmpdir):
    latest_path = os.path.join(top_dir, "tests/db_schema/latest.sql")
    with open(latest_path) as f:
        latest_sql = f.read()

    current_sql, current_path = dump_sql(tmpdir)

    assert current_sql == latest_sql, f"compare_with_latest_sql failed, {current_path} vs. {latest_path}"


def test_new_db(tmpdir, monkeypatch):
    if os.path.exists(test_db):
        os.unlink(test_db)

    monkeypatch.setitem(config["database"], "database", test_db)
    db = Database(LogTool(config), main_service=True)
    db.engine.dispose()

    compare_with_latest_sql(tmpdir)


def test_old_versions(tmpdir, monkeypatch):
    monkeypatch.setitem(config["database"], "database", test_db)

    pattern = os.path.join(top_dir, "tests/db_schema/*.sql")
    for sql in glob.glob(pattern):
        if sql.endswith("/20231009_release_1.0.0.sql"):
            # See test_unsupported_1_0_0() below
            continue
        if os.path.exists(test_db):
            os.unlink(test_db)

        print(f"Testing {sql}")

        # Create database from the SQL file
        conn = sqlite3.connect(test_db)
        with open(sql) as f:
            sql_script = f.read()
        conn.executescript(sql_script)
        conn.close()

        # Upgrade the database
        db = Database(LogTool(config), main_service=True)
        db.engine.dispose()

        # Compare
        compare_with_latest_sql(tmpdir)


def test_unsupported_1_0_0(tmpdir, monkeypatch):
    monkeypatch.setitem(config["database"], "database", test_db)

    if os.path.exists(test_db):
        os.unlink(test_db)

    conn = sqlite3.connect(test_db)
    sql = os.path.join(top_dir, "tests/db_schema/20231009_release_1.0.0.sql")
    with open(sql) as f:
        sql_script = f.read()
    conn.executescript(sql_script)
    conn.close()

    with pytest.raises(SystemExit) as e:
        Database(LogTool(config), main_service=True)
    assert e.value.code == 20
