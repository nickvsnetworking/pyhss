import sys
import json
from flask import Flask, request, jsonify, Response
from flask_restx import Api, Resource, fields, reqparse, abort
from werkzeug.middleware.proxy_fix import ProxyFix
app = Flask(__name__)

import logging
import yaml

with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

import os
import sys
sys.path.append(os.path.realpath('lib'))

#Setup Logging
import logtool

import database
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

app.wsgi_app = ProxyFix(app.wsgi_app)
api = Api(app, version='1.0', title='PyHSS OAM API',
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

ns_oam = api.namespace('oam', description='PyHSS OAM Functions')
ns_pcrf = api.namespace('pcrf', description='PyHSS PCRF Dynamic Functions')
ns_geored = api.namespace('geored', description='PyHSS GeoRedundancy Functions')

parser = reqparse.RequestParser()
parser.add_argument('APN JSON', type=str, help='APN Body')

APN_model = api.schema_model('APN JSON', 
    database.Generate_JSON_Model_for_Flask(APN)
)
Serving_APN_model = api.schema_model('Serving APN JSON', 
    database.Generate_JSON_Model_for_Flask(Serving_APN)
)
AUC_model = api.schema_model('AUC JSON', 
    database.Generate_JSON_Model_for_Flask(AUC)
)
SUBSCRIBER_model = api.schema_model('SUBSCRIBER JSON', 
    database.Generate_JSON_Model_for_Flask(SUBSCRIBER)
)
IMS_SUBSCRIBER_model = api.schema_model('IMS_SUBSCRIBER JSON', 
    database.Generate_JSON_Model_for_Flask(IMS_SUBSCRIBER)
)
TFT_model = api.schema_model('TFT JSON', 
    database.Generate_JSON_Model_for_Flask(TFT)
)
CHARGING_RULE_model = api.schema_model('CHARGING_RULE JSON', 
    database.Generate_JSON_Model_for_Flask(CHARGING_RULE)
)
EIR_model = api.schema_model('EIR JSON', 
    database.Generate_JSON_Model_for_Flask(EIR)
)
IMSI_IMEI_HISTORY_model = api.schema_model('IMSI_IMEI_HISTORY JSON', 
    database.Generate_JSON_Model_for_Flask(IMSI_IMEI_HISTORY)
)
SUBSCRIBER_ATTRIBUTES_model = api.schema_model('SUBSCRIBER_ATTRIBUTES JSON', 
    database.Generate_JSON_Model_for_Flask(SUBSCRIBER_ATTRIBUTES)
)
PCRF_Push_model = api.model('PCRF_Rule', {
    'imsi': fields.String(required=True, description='IMSI of Subscriber to push rule to'),
    'apn_id': fields.Integer(required=True, description='APN_ID of APN to push rule on'),
    'charging_rule_list' : fields.Integer(required=True, description='charging_rule_id to push'),
})
GeoRed_model = api.model('GeoRed', {
    'imsi': fields.String(required=True, description='IMSI of Subscriber to Update'),
    'serving_mme': fields.String(description=SUBSCRIBER.serving_mme.doc),
    'serving_apn' : fields.String(description='Access Point Name of APN'),
    'pcrf_session_id' : fields.String(description=Serving_APN.pcrf_session_id.doc),
    'ue_ip' : fields.String(description=Serving_APN.ue_ip.doc),
    'serving_pgw' : fields.String(description=Serving_APN.serving_pgw.doc),
    'serving_pgw_timestamp' : fields.String(description=Serving_APN.serving_pgw_timestamp.doc),
    'scscf' : fields.String(description=IMS_SUBSCRIBER.scscf.doc),
    'imei' : fields.String(description=EIR.imei.doc),
    'match_response_code' : fields.String(description=EIR.match_response_code.doc),
})

@app.errorhandler(404)
def page_not_found(e):
    return  {"Result": "Not Found"}, 404

@app.after_request
def apply_caching(response):
    response.headers["HSS"] = str(yaml_config['hss']['OriginHost'])
    return response

@ns_apn.route('/<string:apn_id>')
class PyHSS_APN_Get(Resource):
    def get(self, apn_id):
        '''Get all APN data for specified APN ID'''
        try:
            apn_data = database.GetObj(APN, apn_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    def delete(self, apn_id):
        '''Delete all APN data for specified APN ID'''
        try:
            apn_data = database.DeleteObj(APN, apn_id)
            return {"Result": "OK"}, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    @ns_apn.doc('Update APN Object')
    @ns_apn.expect(APN_model)
    def patch(self, apn_id):
        '''Update APN data for specified APN ID'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            apn_data = database.UpdateObj(APN, json_data, apn_id)
            print("Updated object")
            print(apn_data)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500   

@ns_apn.route('/')
class PyHSS_APN(Resource):
    @ns_apn.doc('Create APN Object')
    @ns_apn.expect(APN_model)
    def put(self):
        '''Create new APN'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            apn_id = database.CreateObj(APN, json_data)
            return apn_id, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_apn.route('/list')
class PyHSS_OAM_All_APNs(Resource):
    def get(self):
        '''Get all APNs'''
        try:
            data = database.GetAll(APN)
            return (data), 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_auc.route('/<string:auc_id>')
class PyHSS_AUC_Get(Resource):
    def get(self, auc_id):
        '''Get all AuC data for specified AuC ID'''
        try:
            apn_data = database.GetObj(AUC, auc_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    def delete(self, auc_id):
        '''Delete all AUC data for specified AUC ID'''
        try:
            data = database.DeleteObj(AUC, auc_id)
            return {"Result": "OK"}, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    @ns_auc.doc('Update AUC Object')
    @ns_auc.expect(AUC_model)
    def patch(self, auc_id):
        '''Update AuC data for specified AuC ID'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.UpdateObj(AUC, json_data, auc_id)
            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_auc.route('/iccid/<string:iccid>')
class PyHSS_AUC_Get_ICCID(Resource):
    def get(self, iccid):
        '''Get all AuC data for specified ICCID'''
        try:
            apn_data = database.Get_AuC(iccid=iccid)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_auc.route('/imsi/<string:imsi>')
class PyHSS_AUC_Get_IMSI(Resource):
    def get(self, imsi):
        '''Get all AuC data for specified IMSI'''
        try:
            apn_data = database.Get_AuC(imsi=imsi)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_auc.route('/')
class PyHSS_AUC(Resource):
    @ns_auc.doc('Create AUC Object')
    @ns_auc.expect(AUC_model)
    def put(self):
        '''Create new AUC'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.CreateObj(AUC, json_data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_subscriber.route('/<string:subscriber_id>')
class PyHSS_SUBSCRIBER_Get(Resource):
    def get(self, subscriber_id):
        '''Get all SUBSCRIBER data for specified subscriber_id'''
        try:
            apn_data = database.GetObj(SUBSCRIBER, subscriber_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    def delete(self, subscriber_id):
        '''Delete all data for specified subscriber_id'''
        try:
            data = database.DeleteObj(SUBSCRIBER, subscriber_id)
            return {"Result": "OK"}, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    @ns_subscriber.doc('Update SUBSCRIBER Object')
    @ns_subscriber.expect(SUBSCRIBER_model)
    def patch(self, subscriber_id):
        '''Update SUBSCRIBER data for specified subscriber_id'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.UpdateObj(SUBSCRIBER, json_data, subscriber_id)
            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_subscriber.route('/')
class PyHSS_SUBSCRIBER(Resource):
    @ns_subscriber.doc('Create SUBSCRIBER Object')
    @ns_subscriber.expect(SUBSCRIBER_model)
    def put(self):
        '''Create new SUBSCRIBER'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.CreateObj(SUBSCRIBER, json_data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_subscriber.route('/subscriber/<string:imsi>')
class PyHSS_SUBSCRIBER_IMSI(Resource):
    def get(self, imsi):
        '''Get data for IMSI'''
        try:
            data = database.Get_Subscriber(imsi=imsi, get_attributes=True)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_subscriber.route('/subscriber_msisdn/<string:msisdn>')
class PyHSS_SUBSCRIBER_MSISDN(Resource):
    def get(self, msisdn):
        '''Get data for MSISDN'''
        try:
            data = database.Get_Subscriber(msisdn=msisdn, get_attributes=True)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_subscriber.route('/list')
class PyHSS_SUBSCRIBER_All(Resource):
    def get(self):
        '''Get all Subscribers'''
        try:
            data = database.GetAll(SUBSCRIBER)
            return (data), 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_ims_subscriber.route('/<string:ims_subscriber_id>')
class PyHSS_IMS_SUBSCRIBER_Get(Resource):
    def get(self, ims_subscriber_id):
        '''Get all SUBSCRIBER data for specified ims_subscriber_id'''
        try:
            apn_data = database.GetObj(IMS_SUBSCRIBER, ims_subscriber_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    def delete(self, ims_subscriber_id):
        '''Delete all data for specified ims_subscriber_id'''
        try:
            data = database.DeleteObj(IMS_SUBSCRIBER, ims_subscriber_id)
            return {"Result": "OK"}, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    @ns_ims_subscriber.doc('Update IMS SUBSCRIBER Object')
    @ns_ims_subscriber.expect(IMS_SUBSCRIBER_model)
    def patch(self, ims_subscriber_id):
        '''Update IMS SUBSCRIBER data for specified ims_subscriber'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.UpdateObj(IMS_SUBSCRIBER, json_data, ims_subscriber_id)
            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_ims_subscriber.route('/')
class PyHSS_IMS_SUBSCRIBER(Resource):
    @ns_ims_subscriber.doc('Create IMS SUBSCRIBER Object')
    @ns_ims_subscriber.expect(IMS_SUBSCRIBER_model)
    def put(self):
        '''Create new IMS SUBSCRIBER'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.CreateObj(IMS_SUBSCRIBER, json_data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_ims_subscriber.route('/ims_subscriber_msisdn/<string:msisdn>')
class PyHSS_IMS_SUBSCRIBER_MSISDN(Resource):
    def get(self, msisdn):
        '''Get IMS data for MSISDN'''
        try:
            data = database.Get_IMS_Subscriber(msisdn=msisdn)
            print("Got back: " + str(data))
            return data, 200
        except Exception as E:
            print("Flask Exception: " + str(E))
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_ims_subscriber.route('/ims_subscriber_imsi/<string:imsi>')
class PyHSS_IMS_SUBSCRIBER_IMSI(Resource):
    def get(self, imsi):
        '''Get IMS data for imsi'''
        try:
            data = database.Get_IMS_Subscriber(imsi=imsi)
            print("Got back: " + str(data))
            return data, 200
        except Exception as E:
            print("Flask Exception: " + str(E))
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_ims_subscriber.route('/list')
class PyHSS_IMS_Subscriber_All(Resource):
    def get(self):
        '''Get all IMS Subscribers'''
        try:
            data = database.GetAll(IMS_SUBSCRIBER)
            return (data), 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_tft.route('/<string:tft_id>')
class PyHSS_TFT_Get(Resource):
    def get(self, tft_id):
        '''Get all TFT data for specified tft_id'''
        try:
            apn_data = database.GetObj(TFT, tft_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    def delete(self, tft_id):
        '''Delete all data for specified tft_id'''
        try:
            data = database.DeleteObj(TFT, tft_id)
            return {"Result": "OK"}, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    @ns_ims_subscriber.doc('Update IMS tft_id Object')
    @ns_ims_subscriber.expect(TFT_model)
    def patch(self, tft_id):
        '''Update tft_id data for specified tft_id'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.UpdateObj(TFT, json_data, tft_id)
            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_tft.route('/')
class PyHSS_TFT(Resource):
    @ns_tft.doc('Create TFT Object')
    @ns_tft.expect(TFT_model)
    def put(self):
        '''Create new TFT'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.CreateObj(TFT, json_data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_tft.route('/list')
class PyHSS_TFT_All(Resource):
    def get(self):
        '''Get all TFTs'''
        try:
            data = database.GetAll(TFT)
            return (data), 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_charging_rule.route('/<string:charging_rule_id>')
class PyHSS_Charging_Rule_Get(Resource):
    def get(self, charging_rule_id):
        '''Get all Charging Rule data for specified charging_rule_id'''
        try:
            apn_data = database.GetObj(CHARGING_RULE, charging_rule_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    def delete(self, charging_rule_id):
        '''Delete all data for specified charging_rule_id'''
        try:
            data = database.DeleteObj(CHARGING_RULE, charging_rule_id)
            return {"Result": "OK"}, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    @ns_charging_rule.doc('Update charging_rule_id Object')
    @ns_charging_rule.expect(CHARGING_RULE_model)
    def patch(self, charging_rule_id):
        '''Update charging_rule_id data for specified charging_rule_id'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.UpdateObj(CHARGING_RULE, json_data, charging_rule_id)
            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_charging_rule.route('/')
class PyHSS_Charging_Rule(Resource):
    @ns_charging_rule.doc('Create ChargingRule Object')
    @ns_charging_rule.expect(CHARGING_RULE_model)
    def put(self):
        '''Create new ChargingRule'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.CreateObj(CHARGING_RULE, json_data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_charging_rule.route('/list')
class PyHSS_Charging_Rule_All(Resource):
    def get(self):
        '''Get all Charging Rules'''
        try:
            data = database.GetAll(CHARGING_RULE)
            return (data), 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_eir.route('/<string:eir_id>')
class PyHSS_EIR_Get(Resource):
    def get(self, eir_id):
        '''Get all EIR data for specified eir_id'''
        try:
            eir_data = database.GetObj(EIR, eir_id)
            return eir_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    def delete(self, eir_id):
        '''Delete all data for specified eir_data'''
        try:
            data = database.DeleteObj(EIR, eir_id)
            return {"Result": "OK"}, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    @ns_eir.doc('Update eir Object')
    @ns_eir.expect(EIR_model)
    def patch(self, eir_id):
        '''Update eir_id data for specified eir_id'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.UpdateObj(EIR, json_data, eir_id)
            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_eir.route('/')
class PyHSS_EIR(Resource):
    @ns_eir.doc('Create EIR Object')
    @ns_eir.expect(EIR_model)
    def put(self):
        '''Create new EIR Rule'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.CreateObj(EIR, json_data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_eir.route('/eir_history/<string:attribute>')
class PyHSS_EIR_HISTORY(Resource):
    def get(self, attribute):
        '''Get history for IMSI or IMEI'''
        try:
            data = database.Get_IMEI_IMSI_History(attribute=attribute)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    def delete(self, attribute):
        '''Get Delete for IMSI or IMEI'''
        try:
            data = database.Get_IMEI_IMSI_History(attribute=attribute)
            for record in data:
                database.DeleteObj(IMSI_IMEI_HISTORY, record['imsi_imei_history_id'])
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_eir.route('/list')
class PyHSS_EIR_All(Resource):
    def get(self):
        '''Get all EIR Rules'''
        try:
            data = database.GetAll(EIR)
            return (data), 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_subscriber_attributes.route('/<string:subscriber_id>')
class PyHSS_Attributes_Get(Resource):
    def get(self, subscriber_id):
        '''Get all attributes / values for specified Subscriber ID'''
        try:
            apn_data = database.Get_Subscriber_Attributes(subscriber_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_subscriber_attributes.route('/<string:subscriber_attributes_id>')
class PyHSS_Attributes_Get(Resource):
    def delete(self, subscriber_attributes_id):
        '''Delete specified attribute ID'''
        try:
            data = database.DeleteObj(SUBSCRIBER_ATTRIBUTES, subscriber_attributes_id)
            return {"Result": "OK"}, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

    @ns_subscriber_attributes.doc('Update Attribute Object')
    @ns_subscriber_attributes.expect(SUBSCRIBER_ATTRIBUTES_model)
    def patch(self, subscriber_attributes_id):
        '''Update data for specified attribute ID'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.UpdateObj(SUBSCRIBER_ATTRIBUTES, json_data, subscriber_attributes_id)
            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_subscriber_attributes.route('/')
class PyHSS_Attributes(Resource):
    @ns_subscriber_attributes.doc('Create Attribute Object')
    @ns_subscriber_attributes.expect(SUBSCRIBER_ATTRIBUTES_model)
    def put(self):
        '''Create new Attribute for Subscriber'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database.CreateObj(SUBSCRIBER_ATTRIBUTES, json_data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_oam.route('/diameter_peers')
class PyHSS_OAM_Peers(Resource):
    def get(self):
        '''Get all Diameter Peers'''
        try:
            logObj = logtool.LogTool()
            DiameterPeers = logObj.GetDiameterPeers()
            return DiameterPeers, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_oam.route('/serving_subs')
class PyHSS_OAM_Serving_Subs(Resource):
    def get(self):
        '''Get all Subscribers served by HSS'''
        try:
            data = database.Get_Served_Subscribers()
            print("Got back served Subs: " + str(data))
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_oam.route('/serving_subs_pcrf')
class PyHSS_OAM_Serving_Subs_PCRF(Resource):
    def get(self):
        '''Get all Subscribers served by PCRF'''
        try:
            data = database.Get_Served_PCRF_Subscribers()
            print("Got back served Subs: " + str(data))
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_oam.route('/serving_subs_ims')
class PyHSS_OAM_Serving_Subs_IMS(Resource):
    def get(self):
        '''Get all Subscribers served by IMS'''
        try:
            data = database.Get_Served_IMS_Subscribers()
            print("Got back served Subs: " + str(data))
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_pcrf.route('/pcrf_subscriber_msisdn/<string:imsi>/<string:apn>')
class PyHSS_OAM_Get_PCRF_Subscriber(Resource):
    def get(self, imsi, apn):
        '''Get PCRF data'''
        try:
            #ToDo - Move the mapping an APN name to an APN ID for a sub into the Database functions

            #Resolve Subscriber ID
            subscriber_data = database.Get_Subscriber(imsi=str(imsi))
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
            for apn_id in apn_list:
                print("Getting APN ID " + str(apn_id) + " to see if it matches APN " + str(apn))
                #Get each APN in List
                apn_data = database.Get_APN(apn_id)
                print(apn_data)
                if str(apn_data['apn']).lower() == str(apn).lower():
                    print("Matched named APN with APN ID")
                    apn_id_final = apn_data['apn_id']

            data = database.Get_Serving_APN(subscriber_id=subscriber_data['subscriber_id'], apn_id=apn_id_final)
            data = database.Sanitize_Datetime(data)
            print("Got back: " + str(data))
            return data, 200
        except Exception as E:
            print("Flask Exception: " + str(E))
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_pcrf.route('/')
class PyHSS_PCRF(Resource):
    @ns_pcrf.doc('Push Charging Rule to a Subscriber')
    @ns_pcrf.expect(PCRF_Push_model)
    def put(self):
        '''Push predefined Charging Rule to Subscriber'''
    
        json_data = request.get_json(force=True)
        print("JSON Data sent: " + str(json_data))
        #Get IMSI
        subscriber_data = database.Get_Subscriber(imsi=str(json_data['imsi']))
        print("subscriber_data: " + str(subscriber_data))

        #Get PCRF Session
        pcrf_session_data = database.Get_Serving_APN_Subscriber(subscriber_id=subscriber_data['subscriber_id'], apn_id=json_data['apn_id'])          
        print("pcrf_session_data: " + str(pcrf_session_data))

        #Get Charging Rules
        ChargingRule = database.Get_Charging_Rule(json_data['charging_rule_id'])
        ChargingRule['apn_data'] = database.Get_APN(json_data['apn_id'])
        print("Got ChargingRule: " + str(ChargingRule))

        diameter_host = yaml_config['hss']['OriginHost']                                                        #Diameter Host of this Machine
        OriginRealm = yaml_config['hss']['OriginRealm']
        DestinationRealm = OriginRealm
        mcc = yaml_config['hss']['MCC']                                                                     #Mobile Country Code
        mnc = yaml_config['hss']['MNC']                                                                      #Mobile Network Code
        import diameter
        diameter = diameter.Diameter(diameter_host, DestinationRealm, 'PyHSS-client-API', str(mcc), str(mnc))
        diam_hex = diameter.Request_16777238_258(pcrf_session_data['pcrf_session_id'], ChargingRule, pcrf_session_data['ue_ip'], pcrf_session_data['serving_pgw'], 'ServingRealm.com')
        import time
        logObj = logtool.LogTool()
        logObj.Async_SendRequest(diam_hex, str(pcrf_session_data['serving_pgw']))
        return diam_hex, 200

@ns_pcrf.route('/<string:charging_rule_id>')
class PyHSS_PCRF_Complete(Resource):
    def get(self, charging_rule_id):
        '''Get full Charging Rule + TFTs'''
        try:
            data = database.Get_Charging_Rule(charging_rule_id)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : str(E)}
            return response_json, 500

@ns_geored.route('/')
class PyHSS_Geored(Resource):
    @ns_geored.doc('Create ChargingRule Object')
    @ns_geored.expect(GeoRed_model)
    def patch(self):
        '''Get Geored data Pushed'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent in Geored request: " + str(json_data))
            #Determine what actions to take / update based on keys returned
            response_data = []
            if 'serving_mme' in json_data:
                print("Updating serving MME")
                response_data.append(database.Update_Serving_MME(str(json_data['imsi']), json_data['serving_mme'], propagate=False))
            if 'serving_apn' in json_data:
                print("Updating serving APN")
                response_data.append(database.Update_Serving_APN(str(json_data['imsi']), json_data['serving_apn'], json_data['pcrf_session_id'], json_data['serving_pgw'], json_data['ue_ip'], propagate=False))
            if 'scscf' in json_data:
                print("Updating serving SCSCF")
                response_data.append(database.Update_Serving_CSCF(str(json_data['imsi']), json_data['scscf'], propagate=False))
            if 'imei' in json_data:
                print("Updating EIR")
                response_data.append(database.Store_IMSI_IMEI_Binding(str(json_data['imsi']), str(json_data['imei']), str(json_data['match_response_code']), propagate=False))
            return response_data, 200
        except Exception as E:
            print("Exception when updating: " + str(E))
            response_json = {'result': 'Failed', 'Reason' : str(E), 'Partial Response Data' : str(response_data)}
            return response_json, 500


if __name__ == '__main__':
    app.run(debug=True)
