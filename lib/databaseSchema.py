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

    def execute(self, sql):
        with self.engine.connect() as conn:
            conn.execute(sqlalchemy.text(sql))
            conn.commit()

    def set_version(self, new_version):
        self.logTool.log(
            service="Database",
            level="info",
            message=f"New database schema version is {new_version}",
        )
        self.execute(f"""
            INSERT INTO database_schema_version (upgrade_id, comment)
            VALUES ({int(new_version)}, 'automatic upgrade from PyHSS')
        """)

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

        if not self.table_exists("subscriber"):
            # Assume completely empty database (either because it was just
            # created, or for mysql/postgresql an admin may create the database
            # first before an application accesses it with a different user)
            self.logTool.log(
                service="Database",
                level="debug",
                message="Initializing empty database",
            )
            self.base.metadata.create_all(self.engine)
            self.set_version(self.latest)
        else:
            version = self.get_version()
            self.logTool.log(
                service="Database",
                level="debug",
                message=f"Database already created (schema version: {version})",
            )
            if version > self.latest:
                self.logTool.log(
                    service="Database",
                    level="warning",
                    message=f"Database schema version {version} is higher than latest known version {self.latest}",
                )
