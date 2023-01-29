# API Service

A Flask-Restx based API service is available for all CRUD operations on the database.

You can start this by running:

```shell
export FLASK_APP=PyHSS_API.py
flask run --host=0.0.0.0 --port=8080
```

And browsing to ``http://hssip:8080/docs/``.

From here you'll get the Swagger based API docs with the "try it out" feature.

Note: When creating objects you do not need to set the ID field, for example when creating an API, you do not need to set the api_id - It is created for you.

![Gif showing how to add data to PyHSS via Swagger API](https://github.com/nickvsnetworking/pyhss/raw/master/docs/images/PyHSS_API_Swagger.gif)

For an example of using the API checkout `tests_API.py` which contains examples of working with the RESTful API in Python using the *requests* library.

From the API we can also do some funky things like seeing the Diameter peers connected to PyHSS, and manually triggering inserting Charging Rules to an Active Subscriber on the PyHSS PCRF.

An example systemd file is included in this directory (``API.service``) to run this as a service.
