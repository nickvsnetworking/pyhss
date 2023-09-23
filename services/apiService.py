import sys
import json
from flask import Flask, request, jsonify, Response
from flask_restx import Api, Resource, fields, reqparse, abort
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
import os
sys.path.append(os.path.realpath('../lib'))
import time
import requests
import traceback
import sqlalchemy
import socket
from logtool import LogTool
from diameter import Diameter
from messaging import RedisMessaging
import database
import yaml

with open("../config.yaml", 'r') as stream:
    config = (yaml.safe_load(stream))

siteName = config.get("hss", {}).get("site_name", "")
originHostname = socket.gethostname()
lockProvisioning = config.get('hss', {}).get('lock_provisioning', False)
provisioningKey = config.get('hss', {}).get('provisioning_key', '')
mnc = config.get('hss', {}).get('MNC', '999')
mcc = config.get('hss', {}).get('MCC', '999')
originRealm = config.get('hss', {}).get('OriginRealm', f'mnc{mnc}.mcc{mcc}.3gppnetwork.org')
originHost = config.get('hss', {}).get('OriginHost', f'hss01')
productName = config.get('hss', {}).get('ProductName', f'PyHSS')

redisHost = config.get("redis", {}).get("host", "127.0.0.1")
redisPort = int(config.get("redis", {}).get("port", 6379))
redisMessaging = RedisMessaging(host=redisHost, port=redisPort)

logTool = LogTool(config)

diameterClient = Diameter(
                    redisMessaging=redisMessaging, 
                    logTool=logTool,
                    originHost=originHost, 
                    originRealm=originRealm, 
                    mnc=mnc,
                    mcc=mcc,
                    productName='PyHSS-client-API'
                )

databaseClient = database.Database(logTool=logTool, redisMessaging=redisMessaging)

apiService = Flask(__name__)

APN = database.APN
Serving_APN = database.SERVING_APN
AUC = database.AUC
SUBSCRIBER = database.SUBSCRIBER
IMS_SUBSCRIBER = database.IMS_SUBSCRIBER
TFT = database.TFT
CHARGING_RULE = database.CHARGING_RULE
EIR = database.EIR
IMSI_IMEI_HISTORY = database.IMSI_IMEI_HISTORY
SUBSCRIBER_ATTRIBUTES = database.SUBSCRIBER_ATTRIBUTES
OPERATION_LOG = database.OPERATION_LOG_BASE
SUBSCRIBER_ROUTING = database.SUBSCRIBER_ROUTING

apiService.wsgi_app = ProxyFix(apiService.wsgi_app)
api = Api(apiService, version='1.0', title=f'{siteName + " - " if siteName else ""}{originHostname} - PyHSS OAM API',
    description='Restful API for working with PyHSS',
    doc='/docs/'
)

ns_apn = api.namespace('apn', description='PyHSS APN Functions')
ns_auc = api.namespace('auc', description='PyHSS AUC Functions')
ns_subscriber = api.namespace('subscriber', description='PyHSS SUBSCRIBER Functions')
ns_ims_subscriber = api.namespace('ims_subscriber', description='PyHSS IMS SUBSCRIBER Functions')
ns_tft = api.namespace('tft', description='PyHSS TFT Functions')
ns_charging_rule = api.namespace('charging_rule', description='PyHSS Charging Rule Functions')
ns_eir = api.namespace('eir', description='PyHSS PyHSS Equipment Identity Register')
ns_imsi_imei = api.namespace('imsi_imei', description='PyHSS IMSI / IMEI Mapping')
ns_subscriber_attributes = api.namespace('subscriber_attributes', description='PyHSS Subscriber Attributes')
ns_operation_log = api.namespace('operation_logs', description='PyHSS Operation Logs')
ns_oam = api.namespace('oam', description='PyHSS OAM Functions')
ns_pcrf = api.namespace('pcrf', description='PyHSS PCRF Dynamic Functions')
ns_geored = api.namespace('geored', description='PyHSS GeoRedundancy Functions')
ns_push = api.namespace('push', description='PyHSS Push Async Diameter Command')

parser = reqparse.RequestParser()
parser.add_argument('APN JSON', type=str, help='APN Body')
parser.add_argument('operation_id', type=str, help='Operation ID', location='args')

paginatorParser = reqparse.RequestParser()
paginatorParser.add_argument('page', type=int, required=False, default=0, help='Page number for pagination')
paginatorParser.add_argument('page_size', type=int, required=False, default=config['api'].get('page_size', 100), help='Number of items per page for pagination')

APN_model = api.schema_model('APN JSON', 
    databaseClient.Generate_JSON_Model_for_Flask(APN)
)
Serving_APN_model = api.schema_model('Serving APN JSON', 
    databaseClient.Generate_JSON_Model_for_Flask(Serving_APN)
)
AUC_model = api.schema_model('AUC JSON', 
    databaseClient.Generate_JSON_Model_for_Flask(AUC)
)
SUBSCRIBER_model = api.schema_model('SUBSCRIBER JSON', 
    databaseClient.Generate_JSON_Model_for_Flask(SUBSCRIBER)
)
SUBSCRIBER_ROUTING_model = api.schema_model('SUBSCRIBER_ROUTING JSON', 
    databaseClient.Generate_JSON_Model_for_Flask(SUBSCRIBER_ROUTING)
)
IMS_SUBSCRIBER_model = api.schema_model('IMS_SUBSCRIBER JSON', 
    databaseClient.Generate_JSON_Model_for_Flask(IMS_SUBSCRIBER)
)
TFT_model = api.schema_model('TFT JSON', 
    databaseClient.Generate_JSON_Model_for_Flask(TFT)
)
CHARGING_RULE_model = api.schema_model('CHARGING_RULE JSON', 
    databaseClient.Generate_JSON_Model_for_Flask(CHARGING_RULE)
)
EIR_model = api.schema_model('EIR JSON', 
    databaseClient.Generate_JSON_Model_for_Flask(EIR)
)
IMSI_IMEI_HISTORY_model = api.schema_model('IMSI_IMEI_HISTORY JSON', 
    databaseClient.Generate_JSON_Model_for_Flask(IMSI_IMEI_HISTORY)
)
SUBSCRIBER_ATTRIBUTES_model = api.schema_model('SUBSCRIBER_ATTRIBUTES JSON', 
    databaseClient.Generate_JSON_Model_for_Flask(SUBSCRIBER_ATTRIBUTES)
)

PCRF_Push_model = api.model('PCRF_Rule', {
    'imsi': fields.String(required=True, description='IMSI of Subscriber to push rule to'),
    'apn_id': fields.Integer(required=True, description='APN_ID of APN to push rule on'),
    'charging_rule_id' : fields.Integer(required=True, description='charging_rule_id to push'),
})

Push_CLR_Model = api.model('CLR', {
    'DestinationRealm': fields.String(required=True, description='Destination Realm to set'),
    'DestinationHost': fields.String(required=False, description='Destination Host (Optional)'),
    'cancellationType' : fields.Integer(required=True, default=2, description='Cancellation Type as per 3GPP TS 29.272 / 7.3.24'),
    'diameterPeer': fields.String(required=True, description='Diameter peer to send to'),
})

GeoRed_model = api.model('GeoRed', {
    'imsi': fields.String(required=True, description='IMSI of Subscriber to Update'),
    'serving_mme': fields.String(description=SUBSCRIBER.serving_mme.doc),
    'serving_mme_realm': fields.String(description=SUBSCRIBER.serving_mme_realm.doc),
    'serving_mme_peer': fields.String(description=SUBSCRIBER.serving_mme_peer.doc),
    'serving_mme_timestamp' : fields.String(description=SUBSCRIBER.serving_mme_timestamp.doc),
    'serving_apn' : fields.String(description='Access Point Name of APN'),
    'pcrf_session_id' : fields.String(description=Serving_APN.pcrf_session_id.doc),
    'subscriber_routing' : fields.String(description=Serving_APN.subscriber_routing.doc),
    'serving_pgw' : fields.String(description=Serving_APN.serving_pgw.doc),
    'serving_pgw_realm' : fields.String(description=Serving_APN.serving_pgw_realm.doc),
    'serving_pgw_peer' : fields.String(description=Serving_APN.serving_pgw_peer.doc),
    'serving_pgw_timestamp' : fields.String(description=Serving_APN.serving_pgw_timestamp.doc),
    'scscf' : fields.String(description=IMS_SUBSCRIBER.scscf.doc),
    'scscf_realm' : fields.String(description=IMS_SUBSCRIBER.scscf_realm.doc),
    'scscf_peer' : fields.String(description=IMS_SUBSCRIBER.scscf_peer.doc),
    'scscf_timestamp' : fields.String(description=IMS_SUBSCRIBER.scscf_timestamp.doc),
    'imei' : fields.String(description=EIR.imei.doc),
    'match_response_code' : fields.String(description=EIR.match_response_code.doc),
})

Geored_schema = {
    'serving_mme': "string",
    'serving_mme_realm': "string",
    'serving_mme_peer': "string",
    'serving_mme_timestamp': "string",
    'serving_apn' : "string",
    'pcrf_session_id' : "string",
    'subscriber_routing' : "string",
    'serving_pgw' : "string",
    'serving_pgw_timestamp' : "string",
    'scscf' : "string",
    'imei' : "string",
    'match_response_code' : "string"
}


def no_auth_required(f):
    f.no_auth_required = True
    return f

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if getattr(f, 'no_auth_required', False) or (lockProvisioning == False):
            return f(*args, **kwargs)
        if 'Provisioning-Key' not in request.headers or request.headers['Provisioning-Key'] != config['hss']['provisioning_key']:
            return {'Result': 'Unauthorized - Provisioning-Key Invalid'}, 401
        return f(*args, **kwargs)
    return decorated_function

def auth_before_request():
    if request.path.startswith('/docs') or request.path.startswith('/swagger') or request.path.startswith('/metrics'):
        return None
    if request.endpoint and 'static' not in request.endpoint:
        view_function = apiService.view_functions[request.endpoint]
        if hasattr(view_function, 'view_class'):
            view_class = view_function.view_class
            view_method = getattr(view_class, request.method.lower(), None)
            if view_method:
                if(lockProvisioning == False):
                    return None
                if request.method == 'GET' and not getattr(view_method, 'auth_required', False):
                    return None
                elif request.method in ['POST', 'PUT', 'PATCH', 'DELETE'] and not getattr(view_method, 'no_auth_required', False):
                    pass
                else:
                    return None

        if 'Provisioning-Key' not in request.headers or request.headers['Provisioning-Key'] != config['hss']['provisioning_key']:
            return {'Result': 'Unauthorized - Provisioning-Key Invalid'}, 401
    return None

def handle_exception(e):

    logTool.log(service='API', level='error', message=f"[API] An error occurred: {e}", redisClient=redisMessaging)
    response_json = {'result': 'Failed'}

    if isinstance(e, sqlalchemy.exc.SQLAlchemyError):
        response_json['reason'] = f'A database integrity error occurred: {e}'
        return response_json, 400
    elif isinstance(e, ValueError):
        error_message = str(e)
        if "OperationalError" in error_message:
            response_json['reason'] = f'A database operational error occurred: {e}'
            return response_json, 400
        if "IntegrityError" in error_message:
            response_json['reason'] = f'A database integrity error occurred: {e}'
            return response_json, 400
        if "CSV file does not exist" in error_message:
            response_json['reason'] = f'EIR CSV file is not defined / does not exist'
            return response_json, 410
    else:
        response_json['reason'] = f'An internal server error occurred: {e}'
        logTool.log(service='API', level='error', message=f"[API] Additional Error Information: {traceback.format_exc()}\n{sys.exc_info()[2]}", redisClient=redisMessaging)
        return response_json, 500

apiService.before_request(auth_before_request)

@apiService.errorhandler(404)
def page_not_found(e):
    return  {"Result": "Not Found"}, 404

@apiService.after_request
def apply_caching(response):
    response.headers["HSS"] = str(config['hss']['OriginHost'])
    return response

@ns_apn.route('/<string:apn_id>')
class PyHSS_APN_Get(Resource):
    def get(self, apn_id):
        '''Get all APN data for specified APN ID'''
        try:
            apn_data = databaseClient.GetObj(APN, apn_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    def delete(self, apn_id):
        '''Delete all APN data for specified APN ID'''
        try:
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.DeleteObj(APN, apn_id, False, operation_id)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    @ns_apn.doc('Update APN Object')
    @ns_apn.expect(APN_model)
    def patch(self, apn_id):
        '''Update APN data for specified APN ID'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            apn_data = databaseClient.UpdateObj(APN, json_data, apn_id, False, operation_id)

            print("Updated object")
            print(apn_data)
            return apn_data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)   

@ns_apn.route('/')
class PyHSS_APN(Resource):
    @ns_apn.doc('Create APN Object')
    @ns_apn.expect(APN_model)
    def put(self):
        '''Create new APN'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            apn_id = databaseClient.CreateObj(APN, json_data, False, operation_id)

            return apn_id, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_apn.route('/list')
class PyHSS_OAM_All_APNs(Resource):
    @ns_apn.expect(paginatorParser)
    def get(self):
        '''Get all APNs'''
        try:
            args = paginatorParser.parse_args()
            data = databaseClient.getAllPaginated(APN, args['page'], args['page_size'])
            return (data), 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_auc.route('/<string:auc_id>')
class PyHSS_AUC_Get(Resource):
    def get(self, auc_id):
        '''Get all AuC data for specified AuC ID'''
        try:
            auc_data = databaseClient.GetObj(AUC, auc_id)
            auc_data = databaseClient.Sanitize_Keys(auc_data)
            return auc_data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    def delete(self, auc_id):
        '''Delete all AUC data for specified AUC ID'''
        try:
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.DeleteObj(AUC, auc_id, False, operation_id)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    @ns_auc.doc('Update AUC Object')
    @ns_auc.expect(AUC_model)
    def patch(self, auc_id):
        '''Update AuC data for specified AuC ID'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            auc_data = databaseClient.UpdateObj(AUC, json_data, auc_id, False, operation_id)
            auc_data = databaseClient.Sanitize_Keys(auc_data)
            print("Updated object")
            print(auc_data)
            
            return auc_data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_auc.route('/iccid/<string:iccid>')
class PyHSS_AUC_Get_ICCID(Resource):
    def get(self, iccid):
        '''Get all AuC data for specified ICCID'''
        try:
            auc_data = databaseClient.Get_AuC(iccid=iccid)
            auc_data = databaseClient.Sanitize_Keys(auc_data)
            return auc_data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_auc.route('/imsi/<string:imsi>')
class PyHSS_AUC_Get_IMSI(Resource):
    def get(self, imsi):
        '''Get all AuC data for specified IMSI'''
        try:
            auc_data = databaseClient.Get_AuC(imsi=imsi)
            auc_data = databaseClient.Sanitize_Keys(auc_data)
            return auc_data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_auc.route('/')
class PyHSS_AUC(Resource):
    @ns_auc.doc('Create AUC Object')
    @ns_auc.expect(AUC_model)
    def put(self):
        '''Create new AUC'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.CreateObj(AUC, json_data, False, operation_id)

            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_auc.route('/list')
class PyHSS_AUC_All(Resource):
    @ns_auc.expect(paginatorParser)
    def get(self):
        '''Get all AuC Data (except keys)'''
        try:
            args = paginatorParser.parse_args()
            data = databaseClient.getAllPaginated(AUC, args['page'], args['page_size'])
            return (data), 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_subscriber.route('/<string:subscriber_id>')
class PyHSS_SUBSCRIBER_Get(Resource):
    def get(self, subscriber_id):
        '''Get all SUBSCRIBER data for specified subscriber_id'''
        try:
            apn_data = databaseClient.GetObj(SUBSCRIBER, subscriber_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    def delete(self, subscriber_id):
        '''Delete all data for specified subscriber_id'''
        try:
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.DeleteObj(SUBSCRIBER, subscriber_id, False, operation_id)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    @ns_subscriber.doc('Update SUBSCRIBER Object')
    @ns_subscriber.expect(SUBSCRIBER_model)
    def patch(self, subscriber_id):
        '''Update SUBSCRIBER data for specified subscriber_id'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.UpdateObj(SUBSCRIBER, json_data, subscriber_id, False, operation_id)

            #If the "enabled" flag on the subscriber is now disabled, trigger a CLR
            if 'enabled' in json_data and json_data['enabled'] == False:
                print("Subscriber is now disabled, checking to see if we need to trigger a CLR")
                #See if we have a serving MME set
                try:
                    assert(json_data['serving_mme'])
                    print("Serving MME set - Sending CLR")
                    diameterClient.generateDiameterRequest(
                        requestType='CLR',
                        imsi=json_data['imsi'], 
                        DestinationHost=json_data['serving_mme'], 
                        DestinationRealm=json_data['serving_mme_realm'], 
                        CancellationType=1
                    )
                    print("Sent CLR via Peer " + str(json_data['serving_mme']))
                except:
                    print("No serving MME set - Not sending CLR")

            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_subscriber.route('/')
class PyHSS_SUBSCRIBER(Resource):
    @ns_subscriber.doc('Create SUBSCRIBER Object')
    @ns_subscriber.expect(SUBSCRIBER_model)
    def put(self):
        '''Create new SUBSCRIBER'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.CreateObj(SUBSCRIBER, json_data, False, operation_id)

            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_subscriber.route('/imsi/<string:imsi>')
class PyHSS_SUBSCRIBER_IMSI(Resource):
    def get(self, imsi):
        '''Get data for IMSI'''
        try:
            data = databaseClient.Get_Subscriber(imsi=imsi, get_attributes=True)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_subscriber.route('/msisdn/<string:msisdn>')
class PyHSS_SUBSCRIBER_MSISDN(Resource):
    def get(self, msisdn):
        '''Get data for MSISDN'''
        try:
            data = databaseClient.Get_Subscriber(msisdn=msisdn, get_attributes=True)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_subscriber.route('/list')
class PyHSS_SUBSCRIBER_All(Resource):
    @ns_subscriber.expect(paginatorParser)
    def get(self):
        '''Get all Subscribers'''
        try:
            args = paginatorParser.parse_args()
            data = databaseClient.getAllPaginated(SUBSCRIBER, args['page'], args['page_size'])
            return (data), 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_subscriber.route('/routing/')
class PyHSS_SUBSCRIBER_ROUTING_Create(Resource):
    @ns_ims_subscriber.doc('Create Subscriber Routing Object')
    @ns_ims_subscriber.expect(SUBSCRIBER_ROUTING_model)
    def put(self):
        '''Create new Subscriber Routing Binding'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.CreateObj(SUBSCRIBER_ROUTING, json_data, False, operation_id)

            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_subscriber.route('/routing/<string:subscriber_id>/<string:apn_id>')
class PyHSS_SUBSCRIBER_SUBSCRIBER_ROUTING(Resource):
    def get(self, subscriber_id, apn_id):
        '''Get Subscriber Routing for specified subscriber_id & apn_id'''
        try:
            apn_data = databaseClient.Get_SUBSCRIBER_ROUTING(subscriber_id, apn_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    def delete(self, subscriber_id, apn_id):
        '''Delete Subscriber Routing binding for specified subscriber_id & apn_id'''
        try:
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            apn_data = databaseClient.Get_SUBSCRIBER_ROUTING(subscriber_id, apn_id)
            data = databaseClient.DeleteObj(SUBSCRIBER_ROUTING, apn_data['subscriber_routing_id'], False, operation_id)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_subscriber.route('/routing/<string:subscriber_routing_id>')
class PyHSS_SUBSCRIBER_SUBSCRIBER_ROUTING(Resource):
    @ns_subscriber.doc('Update SUBSCRIBER_ROUTING Object')
    @ns_subscriber.expect(SUBSCRIBER_ROUTING_model)
    def patch(self, subscriber_routing_id):
        '''Update SUBSCRIBER data for specified subscriber_routing_id'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.UpdateObj(SUBSCRIBER_ROUTING, json_data, subscriber_routing_id, False, operation_id)

            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_ims_subscriber.route('/<string:ims_subscriber_id>')
class PyHSS_IMS_SUBSCRIBER_Get(Resource):
    def get(self, ims_subscriber_id):
        '''Get all SUBSCRIBER data for specified ims_subscriber_id'''
        try:
            apn_data = databaseClient.GetObj(IMS_SUBSCRIBER, ims_subscriber_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    def delete(self, ims_subscriber_id):
        '''Delete all data for specified ims_subscriber_id'''
        try:
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.DeleteObj(IMS_SUBSCRIBER, ims_subscriber_id, False, operation_id)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    @ns_ims_subscriber.doc('Update IMS SUBSCRIBER Object')
    @ns_ims_subscriber.expect(IMS_SUBSCRIBER_model)
    def patch(self, ims_subscriber_id):
        '''Update IMS SUBSCRIBER data for specified ims_subscriber'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.UpdateObj(IMS_SUBSCRIBER, json_data, ims_subscriber_id, False, operation_id)

            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_ims_subscriber.route('/')
class PyHSS_IMS_SUBSCRIBER(Resource):
    @ns_ims_subscriber.doc('Create IMS SUBSCRIBER Object')
    @ns_ims_subscriber.expect(IMS_SUBSCRIBER_model)
    def put(self):
        '''Create new IMS SUBSCRIBER'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.CreateObj(IMS_SUBSCRIBER, json_data, False, operation_id)

            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_ims_subscriber.route('/ims_subscriber_msisdn/<string:msisdn>')
class PyHSS_IMS_SUBSCRIBER_MSISDN(Resource):
    def get(self, msisdn):
        '''Get IMS data for MSISDN'''
        try:
            data = databaseClient.Get_IMS_Subscriber(msisdn=msisdn)
            print("Got back: " + str(data))
            return data, 200
        except Exception as E:
            print("Flask Exception: " + str(E))
            return handle_exception(E), 400

@ns_ims_subscriber.route('/ims_subscriber_imsi/<string:imsi>')
class PyHSS_IMS_SUBSCRIBER_IMSI(Resource):
    def get(self, imsi):
        '''Get IMS data for imsi'''
        try:
            data = databaseClient.Get_IMS_Subscriber(imsi=imsi)
            print("Got back: " + str(data))
            return data, 200
        except Exception as E:
            print("Flask Exception: " + str(E))
            return handle_exception(E), 400

@ns_ims_subscriber.route('/list')
class PyHSS_IMS_Subscriber_All(Resource):
    @ns_ims_subscriber.expect(paginatorParser)
    def get(self):
        '''Get all IMS Subscribers'''
        try:
            args = paginatorParser.parse_args()
            data = databaseClient.getAllPaginated(IMS_SUBSCRIBER, args['page'], args['page_size'])
            return (data), 200
        except Exception as E:
            print(E)
            return handle_exception(E), 400

@ns_tft.route('/<string:tft_id>')
class PyHSS_TFT_Get(Resource):
    def get(self, tft_id):
        '''Get all TFT data for specified tft_id'''
        try:
            apn_data = databaseClient.GetObj(TFT, tft_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    def delete(self, tft_id):
        '''Delete all data for specified tft_id'''
        try:
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.DeleteObj(TFT, tft_id, False, operation_id)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    @ns_ims_subscriber.doc('Update IMS tft_id Object')
    @ns_ims_subscriber.expect(TFT_model)
    def patch(self, tft_id):
        '''Update tft_id data for specified tft_id'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.UpdateObj(TFT, json_data, tft_id, False, operation_id)

            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_tft.route('/')
class PyHSS_TFT(Resource):
    @ns_tft.doc('Create TFT Object')
    @ns_tft.expect(TFT_model)
    def put(self):
        '''Create new TFT'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.CreateObj(TFT, json_data, False, operation_id)

            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_tft.route('/list')
class PyHSS_TFT_All(Resource):
    @ns_tft.expect(paginatorParser)
    def get(self):
        '''Get all TFTs'''
        try:
            args = paginatorParser.parse_args()
            data = databaseClient.getAllPaginated(TFT, args['page'], args['page_size'])
            return (data), 200
        except Exception as E:
            print(E)
            return handle_exception(E)
        
@ns_charging_rule.route('/<string:charging_rule_id>')
class PyHSS_Charging_Rule_Get(Resource):
    def get(self, charging_rule_id):
        '''Get all Charging Rule data for specified charging_rule_id'''
        try:
            apn_data = databaseClient.GetObj(CHARGING_RULE, charging_rule_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    def delete(self, charging_rule_id):
        '''Delete all data for specified charging_rule_id'''
        try:
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.DeleteObj(CHARGING_RULE, charging_rule_id, False, operation_id)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    @ns_charging_rule.doc('Update charging_rule_id Object')
    @ns_charging_rule.expect(CHARGING_RULE_model)
    def patch(self, charging_rule_id):
        '''Update charging_rule_id data for specified charging_rule_id'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.UpdateObj(CHARGING_RULE, json_data, charging_rule_id, False, operation_id)

            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_charging_rule.route('/')
class PyHSS_Charging_Rule(Resource):
    @ns_charging_rule.doc('Create ChargingRule Object')
    @ns_charging_rule.expect(CHARGING_RULE_model)
    def put(self):
        '''Create new ChargingRule'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.CreateObj(CHARGING_RULE, json_data, False, operation_id)

            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_charging_rule.route('/list')
class PyHSS_Charging_Rule_All(Resource):
    @ns_charging_rule.expect(paginatorParser)
    def get(self):
        '''Get all Charging Rules'''
        try:
            args = paginatorParser.parse_args()
            data = databaseClient.getAllPaginated(CHARGING_RULE, args['page'], args['page_size'])
            return (data), 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_eir.route('/<string:eir_id>')
class PyHSS_EIR_Get(Resource):
    def get(self, eir_id):
        '''Get all EIR data for specified eir_id'''
        try:
            eir_data = databaseClient.GetObj(EIR, eir_id)
            return eir_data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    def delete(self, eir_id):
        '''Delete all data for specified eir_data'''
        try:
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.DeleteObj(EIR, eir_id, False, operation_id)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    @ns_eir.doc('Update eir Object')
    @ns_eir.expect(EIR_model)
    def patch(self, eir_id):
        '''Update eir_id data for specified eir_id'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.UpdateObj(EIR, json_data, eir_id, False, operation_id)

            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_eir.route('/')
class PyHSS_EIR(Resource):
    @ns_eir.doc('Create EIR Object')
    @ns_eir.expect(EIR_model)
    def put(self):
        '''Create new EIR Rule'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.CreateObj(EIR, json_data, False, operation_id)

            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_eir.route('/eir_history/<string:attribute>')
class PyHSS_EIR_HISTORY(Resource):
    def get(self, attribute):
        '''Get history for IMSI or IMEI'''
        try:
            data = databaseClient.Get_IMEI_IMSI_History(attribute=attribute)
            #Add device info for each entry
            data_w_device_info = []
            for record in data:
                record['imei_result'] = databaseClient.get_device_info_from_TAC(imei=str(record['imei']))
                data_w_device_info.append(record)
            return data_w_device_info, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    def delete(self, attribute):
        '''Get Delete for IMSI or IMEI'''
        try:
            data = databaseClient.Get_IMEI_IMSI_History(attribute=attribute)
            for record in data:
                databaseClient.DeleteObj(IMSI_IMEI_HISTORY, record['imsi_imei_history_id'])
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_eir.route('/eir_history/list')
class PyHSS_EIR_All_History(Resource):
    @ns_eir.expect(paginatorParser)
    def get(self):
        '''Get EIR history for all subscribers'''
        try:
            args = paginatorParser.parse_args()
            data = databaseClient.getAllPaginated(IMSI_IMEI_HISTORY, args['page'], args['page_size'])
            for record in data:
                record['imsi'] = record['imsi_imei'].split(',')[0]
                record['imei'] = record['imsi_imei'].split(',')[1]
            return (data), 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_eir.route('/list')
class PyHSS_EIR_All(Resource):
    @ns_eir.expect(paginatorParser)
    def get(self):
        '''Get all EIR Rules'''
        try:
            args = paginatorParser.parse_args()
            data = databaseClient.getAllPaginated(EIR, args['page'], args['page_size'])
            return (data), 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_eir.route('/lookup_imei/<string:imei>')
class PyHSS_EIR_TAC(Resource):
    def get(self, imei):
        '''Get Device Info from IMEI'''
        try:
            data = databaseClient.get_device_info_from_TAC(imei=imei)
            return (data), 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_subscriber_attributes.route('/list')
class PyHSS_Subscriber_Attributes_All(Resource):
    @ns_subscriber_attributes.expect(paginatorParser)
    def get(self):
        '''Get all Subscriber Attributes'''
        try:
            args = paginatorParser.parse_args()
            data = databaseClient.getAllPaginated(SUBSCRIBER_ATTRIBUTES, args['page'], args['page_size'])
            return (data), 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_subscriber_attributes.route('/<string:subscriber_id>')
class PyHSS_Attributes_Get(Resource):
    def get(self, subscriber_id):
        '''Get all attributes / values for specified Subscriber ID'''
        try:
            apn_data = databaseClient.Get_Subscriber_Attributes(subscriber_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_subscriber_attributes.route('/<string:subscriber_attributes_id>')
class PyHSS_Attributes_Get(Resource):
    def delete(self, subscriber_attributes_id):
        '''Delete specified attribute ID'''
        try:
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.DeleteObj(SUBSCRIBER_ATTRIBUTES, subscriber_attributes_id, False, operation_id)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

    @ns_subscriber_attributes.doc('Update Attribute Object')
    @ns_subscriber_attributes.expect(SUBSCRIBER_ATTRIBUTES_model)
    def patch(self, subscriber_attributes_id):
        '''Update data for specified attribute ID'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.UpdateObj(SUBSCRIBER_ATTRIBUTES, json_data, subscriber_attributes_id, False, operation_id)

            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_subscriber_attributes.route('/')
class PyHSS_Attributes(Resource):
    @ns_subscriber_attributes.doc('Create Attribute Object')
    @ns_subscriber_attributes.expect(SUBSCRIBER_ATTRIBUTES_model)
    def put(self):
        '''Create new Attribute for Subscriber'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            args = parser.parse_args()
            operation_id = args.get('operation_id', None)
            data = databaseClient.CreateObj(SUBSCRIBER_ATTRIBUTES, json_data, False, operation_id)

            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_operation_log.route('/list')
class PyHSS_Operation_Log_List(Resource):
    @ns_operation_log.expect(paginatorParser)
    def get(self):
        '''Get all Operation Logs'''
        try:
            args = paginatorParser.parse_args()
            OperationLogs = databaseClient.get_all_operation_logs(args['page'], args['page_size'])
            return OperationLogs, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_operation_log.route('/last')
class PyHSS_Operation_Log_Last(Resource):
    def get(self):
        '''Get the most recent Operation Log'''
        try:
            OperationLogs = databaseClient.get_last_operation_log()
            return OperationLogs, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_operation_log.route('/list/table/<string:table_name>')
class PyHSS_Operation_Log_List_Table(Resource):
    @ns_operation_log.expect(paginatorParser)
    def get(self, table_name):
        '''Get all Operation Logs for a given table'''
        try:
            args = paginatorParser.parse_args()
            OperationLogs = databaseClient.get_all_operation_logs_by_table(table_name, args['page'], args['page_size'])
            return OperationLogs, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_oam.route('/diameter_peers')
class PyHSS_OAM_Peers(Resource):
    def get(self):
        '''Get all Diameter Peers'''
        try:
            diameterPeers = redisMessaging.getValue("ActiveDiameterPeers")
            return diameterPeers, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_oam.route("/ping")
class PyHSS_OAM_Ping(Resource):
    def get(self):
        """Ping the API to check if it's alive"""
        try:
            apiPingResponse = {"result": "OK"}
            return apiPingResponse, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_oam.route('/rollback_operation/last')
class PyHSS_OAM_Rollback_Last(Resource):
    @auth_required
    def get(self):
        '''Undo the last Insert/Update/Delete operation'''
        try:
            RollbackResponse = databaseClient.rollback_last_change()
            return RollbackResponse, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_oam.route('/rollback_operation/<string:operation_id>')
class PyHSS_OAM_Rollback_Last_Table(Resource):
    @auth_required
    def get(self, operation_id):
        '''Undo the last Insert/Update/Delete operation for a given operation id'''
        try:
            RollbackResponse = databaseClient.rollback_change_by_operation_id(operation_id)
            return RollbackResponse, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_oam.route('/serving_subs')
class PyHSS_OAM_Serving_Subs(Resource):
    def get(self):
        '''Get all Subscribers served by HSS'''
        try:
            data = databaseClient.Get_Served_Subscribers()
            print("Got back served Subs: " + str(data))
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_oam.route('/serving_subs_pcrf')
class PyHSS_OAM_Serving_Subs_PCRF(Resource):
    def get(self):
        '''Get all Subscribers served by PCRF'''
        try:
            data = databaseClient.Get_Served_PCRF_Subscribers()
            print("Got back served Subs: " + str(data))
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_oam.route('/serving_subs_ims')
class PyHSS_OAM_Serving_Subs_IMS(Resource):
    def get(self):
        '''Get all Subscribers served by IMS'''
        try:
            data = databaseClient.Get_Served_IMS_Subscribers()
            print("Got back served Subs: " + str(data))
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_oam.route('/reconcile/ims/<string:imsi>')
class PyHSS_OAM_Reconcile_IMS(Resource):
    def get(self, imsi):
        '''Get current location of IMS Subscriber from all linked HSS nodes'''
        response_dict = {}
        try:
            #Get local database result
            local_result = databaseClient.Get_IMS_Subscriber(imsi=imsi)
            response_dict['localhost'] = {}
            for keys in local_result:
                if 'cscf' in keys:
                    response_dict['localhost'][keys] = local_result[keys]

            for remote_HSS in config['geored']['sync_endpoints']:
                print("Pulling data from remote HSS: " + str(remote_HSS))
                try:
                    response = requests.get(remote_HSS + '/ims_subscriber/ims_subscriber_imsi/' + str(imsi))
                    response_dict[remote_HSS] = {}
                    for keys in response.json():
                        if 'cscf' in keys:
                            response_dict[remote_HSS][keys] = response.json()[keys]
                except Exception as E:
                    print("Exception pulling from " + str(remote_HSS) + " " + str(E))
                    response_dict[remote_HSS] = str(E)
            mismatch_list = []
            #Compare to check they all agree
            for remote_HSS in response_dict:
                for comparitor_hss in response_dict:
                    try:
                        if (response_dict[remote_HSS]['scscf'] != response_dict[comparitor_hss]['scscf']):
                            print("\t Mismatch between " + str(remote_HSS) + " and " + str(comparitor_hss))
                            mismatch_record = {
                                str(remote_HSS) : response_dict[remote_HSS]['scscf'],
                                str(comparitor_hss) : response_dict[comparitor_hss]['scscf'],
                                }
                            mismatch_list.append(mismatch_record)
                    except:
                        continue
            print("mismatch_list: " + str(mismatch_list))
            response_dict['mismatches'] = mismatch_list
            return response_dict, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_pcrf.route('/pcrf_subscriber_imsi/<string:imsi>')
class PyHSS_OAM_Get_PCRF_Subscriber_all_APN(Resource):
    def get(self, imsi):
        '''Get PCRF Data for a Subscriber'''
        try:
            #ToDo - Move the mapping an APN name to an APN ID for a sub into the Database functions
            serving_sub_final = {}
            serving_sub_final['subscriber_data'] = {}
            serving_sub_final['apns'] = {}

            #Resolve Subscriber ID
            subscriber_data = databaseClient.Get_Subscriber(imsi=str(imsi))
            print("subscriber_data: " + str(subscriber_data))
            serving_sub_final['subscriber_data'] = databaseClient.Sanitize_Datetime(subscriber_data)

            #Split the APN list into a list
            apn_list = subscriber_data['apn_list'].split(',')
            print("Current APN List: " + str(apn_list))
            #Remove the default APN from the list
            try:
                apn_list.remove(str(subscriber_data['default_apn']))
            except:
                print("Failed to remove default APN (" + str(subscriber_data['default_apn']) + " from APN List")
                pass
            
            #Add default APN in first position
            apn_list.insert(0, str(subscriber_data['default_apn']))

            #Get APN ID from APN
            for list_apn_id in apn_list:
                print("Getting APN ID " + str(list_apn_id))
                apn_data = databaseClient.Get_APN(list_apn_id)
                print(apn_data)
                try:
                    serving_sub_final['apns'][str(apn_data['apn'])] = {}
                    serving_sub_final['apns'][str(apn_data['apn'])] = databaseClient.Sanitize_Datetime(databaseClient.Get_Serving_APN(subscriber_id=subscriber_data['subscriber_id'], apn_id=list_apn_id))
                except:
                    serving_sub_final['apns'][str(apn_data['apn'])] = {}
                    print("Failed to get Serving APN for APN ID " + str(list_apn_id))

            print("Got back: " + str(serving_sub_final))
            return serving_sub_final, 200
        except Exception as E:
            print("Flask Exception: " + str(E))
            
            return handle_exception(E)


@ns_pcrf.route('/pcrf_subscriber_imsi/<string:imsi>/<string:apn_id>')
class PyHSS_OAM_Get_PCRF_Subscriber(Resource):
    def get(self, imsi, apn_id):
        '''Get PCRF data'''
        try:
            #ToDo - Move the mapping an APN name to an APN ID for a sub into the Database functions
            apn_id_final = None

            #Resolve Subscriber ID
            subscriber_data = databaseClient.Get_Subscriber(imsi=str(imsi))
            print("subscriber_data: " + str(subscriber_data))

            #Split the APN list into a list
            apn_list = subscriber_data['apn_list'].split(',')
            print("Current APN List: " + str(apn_list))
            #Remove the default APN from the list
            try:
                apn_list.remove(str(subscriber_data['default_apn']))
            except:
                print("Failed to remove default APN (" + str(subscriber_data['default_apn']) + " from APN List")
                pass
            #Add default APN in first position
            apn_list.insert(0, str(subscriber_data['default_apn']))

            #Get APN ID from APN
            for list_apn_id in apn_list:
                print("Getting APN ID " + str(list_apn_id) + " to see if it matches APN " + str(apn_id))
                #Get each APN in List
                apn_data = databaseClient.Get_APN(list_apn_id)
                print(apn_data)
                if str(apn_data['apn_id']).lower() == str(apn_id).lower():
                    print("Matched named APN with APN ID")
                    apn_id_final = apn_data['apn_id']

            data = databaseClient.Get_Serving_APN(subscriber_id=subscriber_data['subscriber_id'], apn_id=apn_id_final)
            data = databaseClient.Sanitize_Datetime(data)
            print("Got back: " + str(data))
            return data, 200
        except Exception as E:
            print("Flask Exception: " + str(E))
            
            return handle_exception(E)

@ns_pcrf.route('/')
class PyHSS_PCRF(Resource):
    @ns_pcrf.doc('Push Charging Rule to a Subscriber')
    @ns_pcrf.expect(PCRF_Push_model)
    def put(self):
        '''Push predefined Charging Rule to Subscriber'''
    
        json_data = request.get_json(force=True)
        print("JSON Data sent: " + str(json_data))
        #Get IMSI
        subscriber_data = databaseClient.Get_Subscriber(imsi=str(json_data['imsi']))
        print("subscriber_data: " + str(subscriber_data))

        #Get PCRF Session
        pcrf_session_data = databaseClient.Get_Serving_APN(subscriber_id=subscriber_data['subscriber_id'], apn_id=json_data['apn_id'])          
        print("pcrf_session_data: " + str(pcrf_session_data))

        #Get Charging Rules
        ChargingRule = databaseClient.Get_Charging_Rule(json_data['charging_rule_id'])
        ChargingRule['apn_data'] = databaseClient.Get_APN(json_data['apn_id'])
        print("Got ChargingRule: " + str(ChargingRule))

        diameterRequest = diameterClient.Request_16777238_258(pcrf_session_data['pcrf_session_id'], ChargingRule, pcrf_session_data['subscriber_routing'], pcrf_session_data['serving_pgw'], 'ServingRealm.com')
        connectedPgws = diameterClient.getConnectedPeersByType('pgw')
        for connectedPgw in connectedPgws:
            outboundQueue = f"diameter-outbound-{connectedPgw.get('ipAddress')}-{connectedPgw.get('port')}-{time.time_ns()}"
            outboundMessage = json.dumps({"diameter-outbound": diameterRequest})
            redisMessaging.sendMessage(queue=outboundQueue, message=outboundMessage, queueExpiry=60)
        
        result = {"request": diameterRequest, "destinationClients": connectedPgws}
        return result, 200

@ns_pcrf.route('/<string:charging_rule_id>')
class PyHSS_PCRF_Complete(Resource):
    def get(self, charging_rule_id):
        '''Get full Charging Rule + TFTs'''
        try:
            data = databaseClient.Get_Charging_Rule(charging_rule_id)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_pcrf.route('/subscriber_routing/<string:subscriber_routing>')
class PyHSS_PCRF_SUBSCRIBER_ROUTING(Resource):
    def get(self, subscriber_routing):
        '''Get Subscriber info from Subscriber Routing'''
        try:
            data = databaseClient.Get_UE_by_IP(subscriber_routing)
            return data, 200
        except Exception as E:
            print(E)
            return handle_exception(E)

@ns_geored.route('/')
class PyHSS_Geored(Resource):
    @ns_geored.doc('Create ChargingRule Object')
    @ns_geored.expect(GeoRed_model)
    @no_auth_required
    def patch(self):
        '''Get Geored data Pushed'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent in Geored request: " + str(json_data))
            response_data = []
            if 'serving_mme' in json_data:
                print("Updating serving MME")
                response_data.append(databaseClient.Update_Serving_MME(imsi=str(json_data['imsi']), serving_mme=json_data['serving_mme'], serving_mme_realm=json_data['serving_mme_realm'], serving_mme_peer=json_data['serving_mme_peer'], propagate=False))
                redisMessaging.sendMetric(serviceName='api', metricName='prom_flask_http_geored_endpoints',
                                    metricType='counter', metricAction='inc', 
                                    metricValue=1.0, metricHelp='Number of Geored Pushes Received',
                                    metricLabels={
                                        "endpoint": "HSS",
                                        "geored_host": request.remote_addr,
                                    },
                                    metricExpiry=60)
            if 'serving_apn' in json_data:
                print("Updating serving APN")
                if 'serving_pgw_realm' not in json_data:
                    json_data['serving_pgw_realm'] = None
                if 'serving_pgw_peer' not in json_data:
                    json_data['serving_pgw_peer'] = None
                response_data.append(databaseClient.Update_Serving_APN(
                    imsi=str(json_data['imsi']), 
                    apn=json_data['serving_apn'],
                    pcrf_session_id=json_data['pcrf_session_id'],
                    serving_pgw=json_data['serving_pgw'],
                    subscriber_routing=json_data['subscriber_routing'],
                    serving_pgw_realm=json_data['serving_pgw_realm'],
                    serving_pgw_peer=json_data['serving_pgw_peer'],
                    propagate=False))
                redisMessaging.sendMetric(serviceName='api', metricName='prom_flask_http_geored_endpoints',
                                    metricType='counter', metricAction='inc', 
                                    metricValue=1.0, metricHelp='Number of Geored Pushes Received',
                                    metricLabels={
                                        "endpoint": "PCRF",
                                        "geored_host": request.remote_addr,
                                    },
                                    metricExpiry=60)
            if 'scscf' in json_data:
                print("Updating serving SCSCF")
                if 'scscf_realm' not in json_data:
                    json_data['scscf_realm'] = None
                if 'scscf_peer' not in json_data:
                    json_data['scscf_peer'] = None
                response_data.append(databaseClient.Update_Serving_CSCF(imsi=str(json_data['imsi']), serving_cscf=json_data['scscf'], scscf_realm=str(json_data['scscf_realm']), scscf_peer=str(json_data['scscf_peer']), propagate=False))
                redisMessaging.sendMetric(serviceName='api', metricName='prom_flask_http_geored_endpoints',
                                    metricType='counter', metricAction='inc', 
                                    metricValue=1.0, metricHelp='Number of Geored Pushes Received',
                                    metricLabels={
                                        "endpoint": "IMS",
                                        "geored_host": request.remote_addr,
                                    },
                                    metricExpiry=60)
            if 'imei' in json_data:
                print("Updating EIR")
                response_data.append(databaseClient.Store_IMSI_IMEI_Binding(str(json_data['imsi']), str(json_data['imei']), str(json_data['match_response_code']), propagate=False))
                redisMessaging.sendMetric(serviceName='api', metricName='prom_flask_http_geored_endpoints',
                                    metricType='counter', metricAction='inc', 
                                    metricValue=1.0, metricHelp='Number of Geored Pushes Received',
                                    metricLabels={
                                        "endpoint": "IMEI",
                                        "geored_host": request.remote_addr,
                                    },
                                    metricExpiry=60)
            return response_data, 200
        except Exception as E:
            print("Exception when updating: " + str(E))
            response_json = {'result': 'Failed', 'Reason' : str(E), 'Partial Response Data' : str(response_data)}
            return response_json

    def get(self):
        '''Return the active geored schema'''
        try:
            geored_model_json = {}
            for key in GeoRed_model:
                geored_model_json[key] = 'string'
            return geored_model_json, 200
        except Exception as E:
            print("Exception when returning geored schema: " + str(E))
            response_json = {'result': 'Failed', 'Reason' : "Unable to return Geored Schema: " + str(E)}
            return response_json

@ns_geored.route('/peers')
class PyHSS_Geored_Peers(Resource):
    def get(self):
        '''Return the configured geored peers'''
        try:
            georedEnabled = config.get('geored', {}).get('enabled', False)
            if not georedEnabled:
                return {'result': 'Failed', 'Reason' : "Geored not enabled"}
            georedPeers = config.get('geored', {}).get('endpoints', [])
            return {'peers': georedPeers}, 200
        except Exception as E:
            print("Exception when returning geored peers: " + str(E))
            response_json = {'result': 'Failed', 'Reason' : "Unable to return Geored peers: " + str(E)}
            return response_json

@ns_geored.route('/webhooks')
class PyHSS_Geored_Webhooks(Resource):
    def get(self):
        '''Return the configured geored webhooks'''
        try:
            georedEnabled = config.get('webhooks', {}).get('enabled', False)
            if not georedEnabled:
                return {'result': 'Failed', 'Reason' : "Webhooks not enabled"}
            georedWebhooks = config.get('webhooks', {}).get('endpoints', [])
            return {'endpoints': georedWebhooks}, 200
        except Exception as E:
            print("Exception when returning geored webhooks: " + str(E))
            response_json = {'result': 'Failed', 'Reason' : "Unable to return Geored webhooks: " + str(E)}
            return response_json

@ns_push.route('/clr/<string:imsi>')
class PyHSS_Push_CLR(Resource):
    @ns_push.expect(Push_CLR_Model)
    @ns_push.doc('Push CLR (Cancel Location Request) to MME')
    def put(self, imsi):
        '''Push CLR (Cancel Location Request) to MME'''
        json_data = request.get_json(force=True)
        print("JSON Data sent: " + str(json_data))
        if 'DestinationHost' not in json_data:
            json_data['DestinationHost'] = None
        diam_hex = diameterClient.sendDiameterRequest(
            requestType='CLR',
            imsi=imsi, 
            DestinationHost=json_data['DestinationHost'], 
            DestinationRealm=json_data['DestinationRealm'], 
            CancellationType=json_data['cancellationType']
        )
        return diam_hex, 200

if __name__ == '__main__':
    apiService.run(debug=False)
