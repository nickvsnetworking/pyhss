#!/bin/bash

apt install alembic -y

ln -s ../config.yaml /etc/pyhss/tools/.

pip3 install -r requirements.txt

mkdir alembic/versions

alembic revision --autogenerate -m "$(date +%Y-%m-%d)"