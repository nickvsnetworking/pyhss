# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import sqlalchemy
import sys
import time
from sqlalchemy.engine import Engine
from sqlalchemy_utils import database_exists, create_database


class DatabaseSchema:
    latest = 0

    def __init__(self, logTool, base, engine: Engine, main_service: bool):
        self.logTool = logTool
        self.base = base
        self.engine = engine

        if not self.is_ready():
            if main_service:
                self.init_db()
                self.init_tables()
            else:
                self.wait_until_ready()

    def table_exists(self, table):
        inspector = sqlalchemy.inspect(self.engine)
        return table in inspector.get_table_names()

    def get_version(self):
        ret = 0
        if not self.table_exists("database_schema_version"):
            return ret
        try:
            sql = """
                SELECT upgrade_id
                FROM database_schema_version
                ORDER BY upgrade_id DESC
                LIMIT 1
            """
            with self.engine.connect() as conn:
                result = conn.execute(sqlalchemy.text(sql)).fetchone()
                if result:
                    ret = result[0]
        except Exception:
            pass
        return ret

    def is_ready(self):
        if not database_exists(self.engine.url):
            return False
        return self.get_version() == self.latest

    def wait_until_ready(self):
        self.logTool.log(
            service="Database",
            level="info",
            message="Waiting for the main service to prepare the database",
        )

        for i in range(100):
            time.sleep(0.2)
            if self.is_ready():
                return

        self.logTool.log(
            service="Database",
            level="error",
            message="Database did not get ready. Is pyhss_hss (hssService) running?",
        )
        sys.exit(10)

    def init_db(self):
        # Create database if it does not exist
        if not database_exists(self.engine.url):
            self.logTool.log(
                service="Database",
                level="debug",
                message="Creating database",
            )
            create_database(self.engine.url)
            self.base.metadata.create_all(self.engine)
        else:
            self.logTool.log(
                service="Database",
                level="debug",
                message="Database already created",
            )

    def init_tables(self):
        # Create individual tables if they do not exist
        inspector = sqlalchemy.inspect(self.engine)
        for table_name in self.base.metadata.tables.keys():
            if table_name not in inspector.get_table_names():
                self.logTool.log(
                    service="Database",
                    level="debug",
                    message=f"Creating table {table_name}",
                )
                self.base.metadata.tables[table_name].create(bind=self.engine)
            else:
                self.logTool.log(
                    service="Database",
                    level="debug",
                    message=f"Table {table_name} already exists",
                )
