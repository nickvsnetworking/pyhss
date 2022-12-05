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
        patch_template_data = self.__class__.template_data
        patch_template_data['ki'] = patch_template_data['ki'][::-1]
        r = requests.patch('http://localhost:5001/auc/' + str(self.__class__.auc_id), data=json.dumps(patch_template_data), headers=headers)
        self.assertEqual(patch_template_data, r.json(), "JSON body should match input")

    def test_E_Get_Patched_AUC(self):
        r = requests.get('http://localhost:5001/auc/' + str(self.__class__.auc_id))
        #Add AUC ID into Template for Validating
        self.__class__.template_data['ki'] = self.__class__.template_data['ki'][::-1]
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_F_Delete_Patched_AUC(self):
        r = requests.delete('http://localhost:5001/auc/' + str(self.__class__.auc_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

if __name__ == '__main__':
    logging.basicConfig( stream=sys.stderr )
    logging.getLogger("UnitTestLogger").setLevel( logging.DEBUG )
    unittest.main()