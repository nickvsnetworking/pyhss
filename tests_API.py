import unittest
import requests
import json
import logging
import sys
global log
log= logging.getLogger("UnitTestLogger")

class API_Tests(unittest.TestCase):
    def test_A_API_Response(self):
        r = requests.get('http://localhost:5001/swagger.json')
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

class APN_Tests(unittest.TestCase):
    apn_id = 0
    template_data = {
        "apn": "UnitTest",
        "pgw_address": "10.98.0.20",
        "sgw_address": "10.98.0.10",
        "charging_characteristics": "0800",
        "apn_ambr_dl": 99999,
        "apn_ambr_ul": 99999,
        "qci": 7,
        "arp_priority": 1,
        "arp_preemption_capability": True,
        "arp_preemption_vulnerability": True
        }

    def test_B_create_APN(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put('http://localhost:5001/apn', data=json.dumps(self.__class__.template_data), headers=headers)
        self.__class__.apn_id = r.json()['apn_id']
        log.debug("Created APN ID " + str(self.__class__.apn_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_APN(self):
        r = requests.get('http://localhost:5001/apn/' + str(self.__class__.apn_id))
        #Add APN ID into Template for Validating
        self.__class__.template_data['apn_id'] = self.__class__.apn_id
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_D_Patch_APN(self):
        headers = {"Content-Type": "application/json"}
        patch_template_data = self.__class__.template_data
        patch_template_data['apn'] = 'PatchedValue'
        r = requests.patch('http://localhost:5001/apn/' + str(self.__class__.apn_id), data=json.dumps(patch_template_data), headers=headers)
        self.assertEqual(patch_template_data, r.json(), "JSON body should match input")

    def test_E_Get_Patched_APN(self):
        r = requests.get('http://localhost:5001/apn/' + str(self.__class__.apn_id))
        #Add APN ID into Template for Validating
        self.__class__.template_data['apn'] = 'PatchedValue'
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_F_Delete_Patched_APN(self):
        r = requests.delete('http://localhost:5001/apn/' + str(self.__class__.apn_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

class AUC_Tests(unittest.TestCase):
    auc_id = 0
    template_data = {
    "ki": "fad51018f65affc04e6d56d699df3a76",
    "opc": "fad51018f65affc04e6d56d699df3a76",
    "amf": "8000",
    "sqn": 99
    }

    def test_B_create_AUC(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put('http://localhost:5001/auc', data=json.dumps(self.__class__.template_data), headers=headers)
        self.__class__.auc_id = r.json()['auc_id']
        log.debug("Created AUC ID " + str(self.__class__.auc_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_AUC(self):
        r = requests.get('http://localhost:5001/auc/' + str(self.__class__.auc_id))
        #Add AUC ID into Template for Validating
        self.__class__.template_data['auc_id'] = self.__class__.auc_id
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_D_Patch_AUC(self):
        headers = {"Content-Type": "application/json"}
        self.__class__.template_data['ki'] = "xxxxxx18f65affc04e6d56d699df3a76"
        r = requests.patch('http://localhost:5001/auc/' + str(self.__class__.auc_id), data=json.dumps(self.__class__.template_data), headers=headers)
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_E_Get_Patched_AUC(self):
        r = requests.get('http://localhost:5001/auc/' + str(self.__class__.auc_id))
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_F_Delete_Patched_AUC(self):
        r = requests.delete('http://localhost:5001/auc/' + str(self.__class__.auc_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

class Subscriber_Tests(unittest.TestCase):
    subscriber_id = 0
    apn_secondary = 0
    template_data = {
    "imsi": "001001000000019",
    "enabled": True,
    "msisdn": "123456789",
    "ue_ambr_dl": 999999,
    "ue_ambr_ul": 999999,
    "nam": 0,
    "subscribed_rau_tau_timer": 600,
    }


    def test_A_create_AUC_for_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put('http://localhost:5001/auc', data=json.dumps({"ki": "fad51018f65affc04e6d56d699df3a76","opc": "fad51018f65affc04e6d56d699df3a76","amf": "8000","sqn": 99}), headers=headers)
        log.debug("Created AUC ID " + str(r.json()['auc_id']))
        self.__class__.template_data['auc_id'] = r.json()['auc_id']
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_A_create_APN_for_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put('http://localhost:5001/apn', data=json.dumps({"apn": "UnitTest", "pgw_address": "10.98.0.20", "sgw_address": "10.98.0.10", "charging_characteristics": "0800", "apn_ambr_dl": 99999, "apn_ambr_ul": 99999, "qci": 7, "arp_priority": 1, "arp_preemption_capability": True, "arp_preemption_vulnerability": True}), headers=headers)
        log.debug("Created APN ID " + str(r.json()['apn_id']))
        self.__class__.template_data['default_apn'] = r.json()['apn_id']
        self.__class__.template_data['apn_list'] = '1,2,' + str(r.json()['apn_id'])
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_A_create_another_APN_for_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put('http://localhost:5001/apn', data=json.dumps({"apn": "UnitTest", "pgw_address": "10.98.0.20", "sgw_address": "10.98.0.10", "charging_characteristics": "0800", "apn_ambr_dl": 99999, "apn_ambr_ul": 99999, "qci": 7, "arp_priority": 1, "arp_preemption_capability": True, "arp_preemption_vulnerability": True}), headers=headers)
        log.debug("Created APN ID " + str(r.json()['apn_id']))
        self.__class__.apn_secondary = r.json()['apn_id']
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")



    def test_B_create_Subscriber(self):
        log.debug(self.__class__.template_data)
        headers = {"Content-Type": "application/json"}
        r = requests.put('http://localhost:5001/subscriber', data=json.dumps(self.__class__.template_data), headers=headers)
        self.__class__.subscriber_id = r.json()['subscriber_id']
        log.debug("Created Subscriber ID " + str(self.__class__.subscriber_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_Subscriber(self):
        r = requests.get('http://localhost:5001/subscriber/' + str(self.__class__.subscriber_id))
        #Add Subscriber ID into Template for Validating
        self.__class__.template_data['subscriber_id'] = self.__class__.subscriber_id
        self.__class__.template_data['serving_mme'] = None
        self.__class__.template_data['serving_mme_timestamp'] = None
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_D_Patch_Subscriber(self):
        headers = {"Content-Type": "application/json"}
        self.__class__.template_data['msisdn'] = '123414299213'
        self.__class__.template_data['apn_list'] = self.__class__.template_data['apn_list'] + "," + str(self.__class__.apn_secondary)
        r = requests.patch('http://localhost:5001/subscriber/' + str(self.__class__.subscriber_id), data=json.dumps(self.__class__.template_data), headers=headers)
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_E_Get_Patched_Subscriber(self):
        r = requests.get('http://localhost:5001/subscriber/' + str(self.__class__.subscriber_id))
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_F_Delete_Patched_Subscriber(self):
        r = requests.delete('http://localhost:5001/subscriber/' + str(self.__class__.subscriber_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

class IMS_Subscriber(unittest.TestCase):
    ims_subscriber_id = 0
    template_data = {
        "msisdn": "5231231",
        "msisdn_list": "5231231",
        "imsi": "5231231",
        "ifc_path": "fdasfd.xml",
        "sh_profile": "fdasfd.xml",
    }

    def test_B_create_IMS_Subscriber(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put('http://localhost:5001/ims_subscriber', data=json.dumps(self.__class__.template_data), headers=headers)
        self.__class__.ims_subscriber_id = r.json()['ims_subscriber_id']
        log.debug("Created ims_subscriber_id " + str(self.__class__.ims_subscriber_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_IMS_Subscriber(self):
        r = requests.get('http://localhost:5001/ims_subscriber/' + str(self.__class__.ims_subscriber_id))
        #Add IMS_Subscriber ID into Template for Validating
        self.__class__.template_data['ims_subscriber_id'] = self.__class__.ims_subscriber_id
        self.__class__.template_data['scscf'] = None
        self.__class__.template_data['scscf_timestamp'] = None
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_D_Patch_IMS_Subscriber(self):
        headers = {"Content-Type": "application/json"}
        self.__class__.template_data['msisdn'] = "5132312321"
        r = requests.patch('http://localhost:5001/ims_subscriber/' + str(self.__class__.ims_subscriber_id), data=json.dumps(self.__class__.template_data), headers=headers)
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_E_Get_Patched_IMS_Subscriber(self):
        r = requests.get('http://localhost:5001/ims_subscriber/' + str(self.__class__.ims_subscriber_id))
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_F_Delete_Patched_IMS_Subscriber(self):
        r = requests.delete('http://localhost:5001/ims_subscriber/' + str(self.__class__.ims_subscriber_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))


if __name__ == '__main__':
    logging.basicConfig( stream=sys.stderr )
    logging.getLogger("UnitTestLogger").setLevel( logging.DEBUG )
    unittest.main()