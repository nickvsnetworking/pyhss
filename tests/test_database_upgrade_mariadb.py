# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import pytest
import shlex
import shutil
import sqlglot
import subprocess
from conftest import wait_for_tcp_port
from database import Database
from logtool import LogTool
from pathlib import Path
from pyhss_config import config

top_dir = Path(Path(__file__) / "../..").resolve()
mariadb_port = 33061


@pytest.fixture
def run_mariadbd(tmpdir):
    programs = [
        "mariadb",
        "mariadb-install-db",
        "mariadbd",
    ]
    for program in programs:
        if not shutil.which(program):
            pytest.skip(f"{program} is not installed")
            return

    cmd = [
        "mariadb-install-db",
        "--no-defaults",
        "--auth-root-authentication-method=normal",
        "--skip-test-db",
        f"--datadir={tmpdir}",
    ]
    print(f"+ {cmd}")
    subprocess.run(cmd, check=True)

    cmd = [
        "mariadbd",
        "--no-defaults",
        "--bind-address=127.0.0.1",
        f"--port={mariadb_port}",
        f"--socket={tmpdir}/.socket",
        f"--datadir={tmpdir}",
    ]
    print(f"+ {cmd}")
    proc = subprocess.Popen(cmd)

    try:
        wait_for_tcp_port(mariadb_port)
        cmd = f"mariadb -u root -h 127.0.0.1 -P {mariadb_port} -e 'CREATE DATABASE hss;'"
        print(f"+ {cmd}")
        subprocess.run(cmd, check=True, shell=True)
        yield
    finally:
        proc.kill()


def mariadb_patch_config(monkeypatch):
    monkeypatch.setitem(config["database"], "db_type", "mysql")
    monkeypatch.setitem(config["database"], "server", f"127.0.0.1:{mariadb_port}")
    monkeypatch.setitem(config["database"], "username", "root")
    monkeypatch.setitem(config["database"], "password", "")
    monkeypatch.setitem(config["database"], "database", "hss")


def mariadb_import(tmpdir, sql_file):
    sql_path_orig = os.path.join(top_dir, "tests/db_schema", sql_file)
    sql_path_temp = os.path.join(tmpdir, "import.sql")

    with open(sql_path_orig) as f:
        sql = f.read()
    with open(sql_path_temp, "w") as f:
        sql = sqlglot.transpile(sql, read="sqlite", write="mysql", pretty=True)
        sql = ";\n\n".join(sql) + ";\n"
        f.write(sql)

    cmd = f"mariadb -u root -h 127.0.0.1 -P {mariadb_port} hss < {shlex.quote(sql_path_temp)}"
    print(f"+ {cmd}")
    subprocess.run(cmd, check=True, shell=True)


@pytest.mark.slow
def test_mariadb_new_db(run_mariadbd, monkeypatch):
    mariadb_patch_config(monkeypatch)

    db = Database(LogTool(config), main_service=True)
    db.engine.dispose()


@pytest.mark.slow
def test_mariadb_upgrade_from_1_0_1(run_mariadbd, monkeypatch, tmpdir):
    mariadb_patch_config(monkeypatch)
    mariadb_import(tmpdir, "20240125_release_1.0.1.sql")

    db = Database(LogTool(config), main_service=True)
    db.engine.dispose()


@pytest.mark.slow
def test_mariadb_unsupported_1_0_0(run_mariadbd, monkeypatch, tmpdir):
    mariadb_patch_config(monkeypatch)
    mariadb_import(tmpdir, "20231009_release_1.0.0.sql")

    with pytest.raises(SystemExit) as e:
        Database(LogTool(config), main_service=True)
    assert e.value.code == 20
