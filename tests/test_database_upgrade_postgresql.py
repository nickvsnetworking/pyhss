# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import glob
import importlib
import os
import pytest
import re
import sqlglot
import subprocess

from conftest import wait_for_tcp_port
from database import Database
from logtool import LogTool
from pathlib import Path
from pyhss_config import config

top_dir = Path(Path(__file__) / "../..").resolve()
postgresql_port = 54321


@pytest.fixture
def run_postgresql(tmpdir):
    initdb = glob.glob("/usr/lib/postgresql/*/bin/initdb")
    postgres = glob.glob("/usr/lib/postgresql/*/bin/postgres")
    createdb = glob.glob("/usr/lib/postgresql/*/bin/createdb")
    psql = glob.glob("/usr/lib/postgresql/*/bin/psql")
    if not initdb or not postgres or not createdb or not psql:
        pytest.skip("postgresql is not installed")
        return
    if not importlib.util.find_spec("psycopg2"):
        # SQLAlchemy needs this to connect to PostgreSQL servers
        pytest.skip("python module psycopg2 is not installed")
        return

    cmd = [initdb[0], f"-D{tmpdir}", "-Uuser", "--no-sync"]
    print(f"+ {cmd}")
    subprocess.run(cmd, check=True)

    cmd = [postgres[0], f"-D{tmpdir}", f"-p{postgresql_port}", f"-k{tmpdir}"]
    print(f"+ {cmd}")
    proc = subprocess.Popen(cmd)

    try:
        wait_for_tcp_port(postgresql_port)
        cmd = [createdb[0], "-h127.0.0.1", f"-p{postgresql_port}", "-Uuser", "hss"]
        print(f"+ {cmd}")
        subprocess.run(cmd, check=True)
        yield
    finally:
        proc.kill()


def postgresql_patch_config(monkeypatch):
    monkeypatch.setitem(config["database"], "db_type", "postgresql")
    monkeypatch.setitem(config["database"], "server", f"127.0.0.1:{postgresql_port}")
    monkeypatch.setitem(config["database"], "username", "user")
    monkeypatch.setitem(config["database"], "password", "")
    monkeypatch.setitem(config["database"], "database", "hss")


def postgresql_import(tmpdir, sql_file):
    sql_path_orig = os.path.join(top_dir, "tests/db_schema", sql_file)
    sql_path_temp = os.path.join(tmpdir, "import.sql")

    with open(sql_path_orig) as f:
        sql = f.read()
    with open(sql_path_temp, "w") as f:
        sql = sqlglot.transpile(sql, read="sqlite", write="postgres", pretty=True)
        sql = ";\n\n".join(sql) + ";\n"
        # Workaround for https://github.com/tobymao/sqlglot/issues/6596
        # Can be removed after sqlglot > v28.5.0 is released
        sql = re.sub(r"(PRIMARY KEY\s*\(\s*\w+)(\s*NULLS\s+FIRST\s*\))", r"\1)", sql)
        f.write(sql)

    psql = glob.glob("/usr/lib/postgresql/*/bin/psql")
    cmd = [
        psql[0],
        "-h127.0.0.1",
        f"-p{postgresql_port}",
        "-Uuser",
        "-dhss",
        f"-f{sql_path_temp}",
        "-vON_ERROR_STOP=1",
    ]
    print(f"+ {cmd}")
    subprocess.run(cmd, check=True)


@pytest.mark.slow
def test_postgresql_new_db(run_postgresql, monkeypatch):
    postgresql_patch_config(monkeypatch)

    db = Database(LogTool(config), main_service=True)
    db.engine.dispose()


@pytest.mark.slow
def test_postgresql_upgrade_from_1_0_1(run_postgresql, monkeypatch, tmpdir):
    postgresql_patch_config(monkeypatch)
    postgresql_import(tmpdir, "20240125_release_1.0.1.sql")

    db = Database(LogTool(config), main_service=True)
    db.engine.dispose()


@pytest.mark.slow
def test_postgresql_unsupported_1_0_0(run_postgresql, monkeypatch, tmpdir):
    postgresql_patch_config(monkeypatch)
    postgresql_import(tmpdir, "20231009_release_1.0.0.sql")

    with pytest.raises(SystemExit) as e:
        Database(LogTool(config), main_service=True)
    assert e.value.code == 20
