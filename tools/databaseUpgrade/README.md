# Database Upgrade

Database upgrades are currently limited to semi-automation.

Alembic is used to handle database schema upgades.

This will not give a foolproof upgrade, ensure you read the generated scripts.
For best results (and in production environments), read lib/database.py and compare each base object to the table in your database.
Types for columns should also be checked.

# Usage

1. Ensure that `config.yaml` is populated with the correct database credentials.

2. Navigate to `tools/databaseUpgrade`

2. `pip3 install -r requirements.txt`

3. `alembic revision --autogenerate -m "Name your upgrade"`

4. `alembic upgrade head`