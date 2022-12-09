# PyHSS - Database Notes
PyHSS now uses Python SQLalchemy to abstract away the database component.

Tested backends are Postgres and MySQL, but in theory any database supporting SQLalchemy could be used.

The schema is quite simple, but rather than interacting directly with the Schema, a RESTful API exists for adding/updating/removing Subscribers, IMS Subscribers, SIMs and APNs.