# import imp
# from flask import request,  jsonify, Response
# from app import app
import sys
import logging
import requests
from urllib3.exceptions import InsecureRequestWarning
# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
from werkzeug.datastructures import FileStorage
import time
sys.path.append('../')
sys.path.append('../lib/')
import database
import os
import yaml
with open(os.path.dirname(__file__) + "/config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

from flask import Flask, request, jsonify, Response
from flask_restx import Api, Resource, fields, reqparse, abort
from werkzeug.middleware.proxy_fix import ProxyFix
import subprocess
import json
app = Flask(__name__)


app.wsgi_app = ProxyFix(app.wsgi_app)
api = Api(app, version='1.0', title='PyHSS OAM API',
    description='Restful API for working with HSS',
    doc='/docs/'
)

ns = api.namespace('PyHSS', description='PyHSS API Functions')

@ns.route('/<string:imsi>')
class PyHSS(Resource):

    def get(self, imsi):
        '''Get all Subscriber data for specified IMSI'''
        try:
            subscriber_details = database.GetSubscriberInfo(imsi)
            return subscriber_details, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "Sub not found " + str(imsi)}
            return jsonify(response_json), 404



if __name__ == '__main__':
    app.run(debug=True)
