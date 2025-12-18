# PyHSS - Database Notes
PyHSS now uses Python SQLalchemy to abstract away the database component.

Tested backends are Postgres, MySQL and sqlite but in theory any database
supporting SQLalchemy could be used.

The schema is quite simple, but rather than interacting directly with the
Schema, a [RESTful API](API.md) allows for easy, safe CRUD operations on the
subscriber data.

If REST isn't your jam and you instead want to interact directly with Python,
`database.py` can be imported into your project and contains all the same hooks
as the API.

## Changing the Database Schema

PyHSS automatically upgrades database schemas that were created with PyHSS
version 1.0.1 or higher, and has CI tests that ensure this keeps working with
SQLite, MySQL and PostgreSQL. Make it work with your changes by following the
steps below.

### Step-by-Step Instructions

* Add new tables or columns to `lib/database.py`.
* Adjust `lib/databaseSchema.py`:
  * Increase `latest` by one.
  * Add a new `upgrade_to_v…(self)` method to `class DatabaseSchema`.
  * Call the new method in `upgrade_all(self)`.
* Run `pytest -k test_sqlite_new_db` and copy
  `/tmp/pytest-of-…/pytest-current/test_sqlite_new_db0/current_db.sql` to
  `tests/db_schema/latest.sql`.
* Run `pytest` and adjust failing test cases, e.g. `test_API.py` may need
  adjustments.

### Examples

<details>
<summary>Example: New Column</summary>

```diff
diff --git a/lib/database.py b/lib/database.py
index f00bf39..7731685 100755
--- a/lib/database.py
+++ b/lib/database.py
@@ -70,6 +70,7 @@ class AUC(Base):
     opc = Column(String(32), doc='SIM Key - Network Operators key OPc', nullable=False)
     amf = Column(String(4), doc='Authentication Management Field', nullable=False)
     sqn = Column(BigInteger, doc='Authentication sequence number')
+    my_new_column = Column(Integer, default=None, doc='Description for the new column')
     iccid = Column(String(20), unique=True, doc='Integrated Circuit Card Identification Number')
     imsi = Column(String(18), unique=True, doc='International Mobile Subscriber Identity')
     batch_name = Column(String(20), doc='Name of SIM Batch')
diff --git a/lib/databaseSchema.py b/lib/databaseSchema.py
index 62c4390..c52b258 100644
--- a/lib/databaseSchema.py
+++ b/lib/databaseSchema.py
@@ -8,7 +8,7 @@ from sqlalchemy_utils import database_exists, create_database


 class DatabaseSchema:
-    latest = 1
+    latest = 2

     def __init__(self, logTool, base, engine: Engine, main_service: bool):
         self.logTool = logTool
@@ -203,5 +203,13 @@ class DatabaseSchema:
         self.add_column("subscriber", "serving_vlr_timestamp", "DATETIME")
         self.set_version(1)

+    def upgrade_to_v2(self):
+        if self.get_version() >= 2:
+            return
+        self.upgrade_msg(2)
+        self.add_column("auc", "my_new_column", "INTEGER")
+        self.set_version(2)
+
     def upgrade_all(self):
         self.upgrade_from_20240603_release_1_0_1()
+        self.upgrade_to_v2()
diff --git a/tests/db_schema/latest.sql b/tests/db_schema/latest.sql
index 4c10b77..a3f6ebb 100644
--- a/tests/db_schema/latest.sql
+++ b/tests/db_schema/latest.sql
@@ -48,6 +48,7 @@ CREATE TABLE auc (
        puk2 VARCHAR(20),
        sim_vendor VARCHAR(20),
        sqn BIGINT,
+       my_new_column INTEGER,
        PRIMARY KEY (auc_id),
        UNIQUE (iccid),
        UNIQUE (imsi)
diff --git a/tests/test_API.py b/tests/test_API.py
index 412c0ba..a83c377 100644
--- a/tests/test_API.py
+++ b/tests/test_API.py
@@ -96,6 +96,7 @@ class AUC_Tests(unittest.TestCase):
     "opc": '44d51018f65affc04e6d56d699df3a76',
     "amf": "8000",
     "sqn": 99,
+    "my_new_column": None,
     'batch_name': None,
     'esim': False,
     'iccid': None,
```
</details>

<details>
<summary>Example: New Table</summary>

```diff
diff --git a/lib/database.py b/lib/database.py
index 9e26beb..9e2ba9b 100755
--- a/lib/database.py
+++ b/lib/database.py
@@ -40,6 +40,13 @@ class DATABASE_SCHEMA_VERSION(Base):
     comment = Column(String(512), doc="Notes about this version upgrade")
     date = Column(DateTime(timezone=True), server_default=sqlalchemy.sql.func.now(), doc="When the upgrade was done")
 
+class NEW_TABLE(Base):
+    __tablename__ = 'new_table'
+    my_id = Column(Integer, primary_key=True)
+    # put more columns here
+
 class APN(Base):
     __tablename__ = 'apn'
     apn_id = Column(Integer, primary_key=True, doc='Unique ID of APN')
diff --git a/lib/databaseSchema.py b/lib/databaseSchema.py
index eb35dcc..f6235b4 100644
--- a/lib/databaseSchema.py
+++ b/lib/databaseSchema.py
@@ -8,7 +8,7 @@ from sqlalchemy_utils import database_exists, create_database
 
 
 class DatabaseSchema:
-    latest = 1
+    latest = 2
 
     def __init__(self, logTool, base, engine: Engine, main_service: bool):
         self.logTool = logTool
@@ -223,5 +223,13 @@ class DatabaseSchema:
         self.add_column("subscriber", "serving_vlr_timestamp", "DATETIME")
         self.set_version(1)
 
+    def upgrade_to_v2(self):
+        if self.get_version() >= 2:
+            return
+        self.upgrade_msg(2)
+        self.base.metadata.tables["new_table"].create(bind=self.engine)
+        self.set_version(2)
+
     def upgrade_all(self):
         self.upgrade_from_20240603_release_1_0_1()
+        self.upgrade_to_v2()
diff --git a/tests/db_schema/latest.sql b/tests/db_schema/latest.sql
index 4c10b77..d95da7d 100644
--- a/tests/db_schema/latest.sql
+++ b/tests/db_schema/latest.sql
@@ -131,6 +131,13 @@ CREATE TABLE ims_subscriber (
        PRIMARY KEY (ims_subscriber_id),
        UNIQUE (msisdn)
 );
+CREATE TABLE new_table (
+       my_id VARCHAR(50) NOT NULL,
+       PRIMARY KEY (my_id)
+);
 CREATE TABLE operation_log (
        apn_id INTEGER,
        auc_id INTEGER,
```
</details>
