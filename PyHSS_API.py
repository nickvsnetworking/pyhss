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
        'apn': {'type': 'string'},
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
    

@ns.route('/apn')
class PyHSS_APN(Resource):
    @ns.doc('Create APN Object')
    @ns.expect(todo)
    def put(self):
        '''Create new APN'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            apn_id = database_new2.CreateAPN(json_data)
            return {"apn_id" : int(apn_id)}, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "Failed to create APN"}
            return jsonify(response_json), 404


    @ns.doc('Update APN Object')
    @ns.expect(todo)
    def patch(self):
        '''Update APN data for specified APN ID'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            apn_data = database_new2.UpdateAPN(json_data)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "Failed to update"}
            return jsonify(response_json), 404

if __name__ == '__main__':
    app.run(debug=True)
