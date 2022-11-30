import sys
import json
from flask import Flask, request, jsonify, Response
from flask_restx import Api, Resource, fields, reqparse, abort
from werkzeug.middleware.proxy_fix import ProxyFix
app = Flask(__name__)
import database_new2

app.wsgi_app = ProxyFix(app.wsgi_app)
api = Api(app, version='1.0', title='PyHSS OAM API',
    description='Restful API for working with PyHSS',
    doc='/docs/'
)

ns = api.namespace('PyHSS', description='PyHSS API Functions')

parser = reqparse.RequestParser()
parser.add_argument('APN JSON', type=str, help='APN Body')

todo = api.schema_model('Todo', {
    'properties': {
        'id': {
            'type': 'string'
        },
        'task': {
            'type': 'string'
        }
    },
    'type': 'object'
})

@ns.route('/apn/<string:apn_id>')
class PyHSS_APN_Get(Resource):
    def get(self, apn_id):
        '''Get all APN data for specified APN ID'''
        try:
            apn_data = database_new2.GetAPN(apn_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "APN ID not found " + str(apn_id)}
            return jsonify(response_json), 404

    def delete(self, apn_id):
        '''Delete all APN data for specified APN ID'''
        try:
            apn_data = database_new2.DeleteAPN(apn_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "APN ID not found " + str(apn_id)}
            return jsonify(response_json), 404
    
    @api.doc(parser=parser)
    def patch(self, apn_id):
        '''Update APN data for specified APN ID'''
        try:
            apn_data = database_new2.DeleteAPN(apn_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "APN ID not found " + str(apn_id)}
            return jsonify(response_json), 404

@ns.route('/apn')
class PyHSS_APN(Resource):
    @ns.doc('create_todo')
    @ns.expect(todo)
    def put(self, apn_id):
        '''Get all APN data for specified APN ID'''
        try:
            apn_data = database_new2.GetAPN(apn_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "APN ID not found " + str(apn_id)}
            return jsonify(response_json), 404

    @ns.doc('Create an APN Object')
    def post(self):
        json_data = request.get_json(force=True)
        return json_data, 201

if __name__ == '__main__':
    app.run(debug=True)
