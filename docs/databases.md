# PyHSS - Database Notes
PyHSS now uses Python SQLalchemy to abstract away the database component.

Tested backends are Postgres and MySQL, but in theory any database supporting SQLalchemy could be used.

The schema is quite simple, but rather than interacting directly with the Schema, a [RESTful API](api.md) allows for easy, safe CRUD operations on the subscriber data.

If REST isn't your jam and you instead want to interact directly with Python, `database.py` can be imported into your project and contains all the same hooks as the API.
