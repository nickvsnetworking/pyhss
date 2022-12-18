import unittest
import requests
import json
import logging
import sys
global log
log= logging.getLogger("UnitTestLogger")
base_url = 'http://localhost:5000'

class API_Tests(unittest.TestCase):
    def test_A_API_Response(self):
        r = requests.get(str(base_url) + '/swagger.json')
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
        "charging_rule_id": None,
        "ip_version": 4,
        "arp_priority": 1,
        "arp_preemption_capability": True,
        "arp_preemption_vulnerability": True
        }

    def test_B_create_APN(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/apn', data=json.dumps(self.__class__.template_data), headers=headers)
        self.__class__.apn_id = r.json()['apn_id']
        log.debug("Created APN ID " + str(self.__class__.apn_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_APN(self):
        r = requests.get(str(base_url) + '/apn/' + str(self.__class__.apn_id))
        #Add APN ID into Template for Validating
        self.__class__.template_data['apn_id'] = self.__class__.apn_id
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_D_Patch_APN(self):
        headers = {"Content-Type": "application/json"}
        patch_template_data = self.__class__.template_data
        patch_template_data['apn'] = 'PatchedValue'
        r = requests.patch(str(base_url) + '/apn/' + str(self.__class__.apn_id), data=json.dumps(patch_template_data), headers=headers)
        self.assertEqual(patch_template_data, r.json(), "JSON body should match input")

    def test_E_Get_Patched_APN(self):
        r = requests.get(str(base_url) + '/apn/' + str(self.__class__.apn_id))
        #Add APN ID into Template for Validating
        self.__class__.template_data['apn'] = 'PatchedValue'
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_F_Delete_Patched_APN(self):
        r = requests.delete(str(base_url) + '/apn/' + str(self.__class__.apn_id))
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
        r = requests.put(str(base_url) + '/auc', data=json.dumps(self.__class__.template_data), headers=headers)
        self.__class__.auc_id = r.json()['auc_id']
        log.debug("Created AUC ID " + str(self.__class__.auc_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_AUC(self):
        r = requests.get(str(base_url) + '/auc/' + str(self.__class__.auc_id))
        #Add AUC ID into Template for Validating
        self.__class__.template_data['auc_id'] = self.__class__.auc_id
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_D_Patch_AUC(self):
        headers = {"Content-Type": "application/json"}
        self.__class__.template_data['ki'] = "xxxxxx18f65affc04e6d56d699df3a76"
        r = requests.patch(str(base_url) + '/auc/' + str(self.__class__.auc_id), data=json.dumps(self.__class__.template_data), headers=headers)
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_E_Get_Patched_AUC(self):
        r = requests.get(str(base_url) + '/auc/' + str(self.__class__.auc_id))
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_F_Delete_Patched_AUC(self):
        r = requests.delete(str(base_url) + '/auc/' + str(self.__class__.auc_id))
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
        r = requests.put(str(base_url) + '/auc', data=json.dumps({"ki": "fad51018f65affc04e6d56d699df3a76","opc": "fad51018f65affc04e6d56d699df3a76","amf": "8000","sqn": 99}), headers=headers)
        log.debug("Created AUC ID " + str(r.json()['auc_id']))
        self.__class__.template_data['auc_id'] = r.json()['auc_id']
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_A_create_APN_for_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/apn', data=json.dumps({"apn": "UnitTest", "pgw_address": "10.98.0.20", "sgw_address": "10.98.0.10", "charging_characteristics": "0800", "apn_ambr_dl": 99999, "apn_ambr_ul": 99999, "qci": 7, "arp_priority": 1, "arp_preemption_capability": True, "arp_preemption_vulnerability": True}), headers=headers)
        log.debug("Created APN ID " + str(r.json()['apn_id']))
        self.__class__.template_data['default_apn'] = r.json()['apn_id']
        self.__class__.template_data['apn_list'] = '1,2,' + str(r.json()['apn_id'])
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_A_create_another_APN_for_Sub(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/apn', data=json.dumps({"apn": "UnitTest", "pgw_address": "10.98.0.20", "sgw_address": "10.98.0.10", "charging_characteristics": "0800", "apn_ambr_dl": 99999, "apn_ambr_ul": 99999, "qci": 7, "arp_priority": 1, "arp_preemption_capability": True, "arp_preemption_vulnerability": True}), headers=headers)
        log.debug("Created APN ID " + str(r.json()['apn_id']))
        self.__class__.apn_secondary = r.json()['apn_id']
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")



    def test_B_create_Subscriber(self):
        log.debug(self.__class__.template_data)
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/subscriber', data=json.dumps(self.__class__.template_data), headers=headers)
        self.__class__.subscriber_id = r.json()['subscriber_id']
        log.debug("Created Subscriber ID " + str(self.__class__.subscriber_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_Subscriber(self):
        r = requests.get(str(base_url) + '/subscriber/' + str(self.__class__.subscriber_id))
        #Add Subscriber ID into Template for Validating
        self.__class__.template_data['subscriber_id'] = self.__class__.subscriber_id
        self.__class__.template_data['serving_mme'] = None
        self.__class__.template_data['serving_mme_timestamp'] = None
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_D_Patch_Subscriber(self):
        headers = {"Content-Type": "application/json"}
        self.__class__.template_data['msisdn'] = '123414299213'
        self.__class__.template_data['apn_list'] = self.__class__.template_data['apn_list'] + "," + str(self.__class__.apn_secondary)
        r = requests.patch(str(base_url) + '/subscriber/' + str(self.__class__.subscriber_id), data=json.dumps(self.__class__.template_data), headers=headers)
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_E_Get_Patched_Subscriber(self):
        r = requests.get(str(base_url) + '/subscriber/' + str(self.__class__.subscriber_id))
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_F_Get_Patched_Subscriber_by_MSISDN(self):
        r = requests.get(str(base_url) + '/oam/subscriber_msisdn/' + str(self.__class__.template_data['msisdn']))
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_Z_Delete_Patched_Subscriber(self):
        r = requests.delete(str(base_url) + '/subscriber/' + str(self.__class__.subscriber_id))
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
        r = requests.put(str(base_url) + '/ims_subscriber', data=json.dumps(self.__class__.template_data), headers=headers)
        self.__class__.ims_subscriber_id = r.json()['ims_subscriber_id']
        log.debug("Created ims_subscriber_id " + str(self.__class__.ims_subscriber_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_IMS_Subscriber(self):
        r = requests.get(str(base_url) + '/ims_subscriber/' + str(self.__class__.ims_subscriber_id))
        #Add IMS_Subscriber ID into Template for Validating
        self.__class__.template_data['ims_subscriber_id'] = self.__class__.ims_subscriber_id
        self.__class__.template_data['scscf'] = None
        self.__class__.template_data['scscf_timestamp'] = None
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_D_Patch_IMS_Subscriber(self):
        headers = {"Content-Type": "application/json"}
        self.__class__.template_data['msisdn'] = "5132312321"
        r = requests.patch(str(base_url) + '/ims_subscriber/' + str(self.__class__.ims_subscriber_id), data=json.dumps(self.__class__.template_data), headers=headers)
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_E_Get_Patched_IMS_Subscriber(self):
        r = requests.get(str(base_url) + '/ims_subscriber/' + str(self.__class__.ims_subscriber_id))
        self.assertEqual(self.__class__.template_data, r.json(), "JSON body should match input")

    def test_F_Delete_Patched_IMS_Subscriber(self):
        r = requests.delete(str(base_url) + '/ims_subscriber/' + str(self.__class__.ims_subscriber_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

class ChargingRule_Tests(unittest.TestCase):
    tft_id = 0
    charging_rule_id = 0
    #Define TFTs
    tft_template1 = {
        'tft_group_id' : 1,
        'tft_string' : 'permit out ip from any to any',
        'direction' : 1
    }
    tft_template2 = {
        'tft_group_id' : 1,
        'tft_string' : 'permit out ip from any to any',
        'direction' : 2
    }

    charging_rule_template = {
        'rule_name' : 'charging_rule_test2',
        'qci' : 4,
        'arp_priority' : 5,
        'arp_preemption_capability' : True,
        'arp_preemption_vulnerability' : False,
        'mbr_dl' : 128000,
        'mbr_ul' : 128000,
        'gbr_dl' : 128000,
        'gbr_ul' : 128000,
        'tft_group_id' : 1,
        'precedence' : 100
        }


    def test_A_create_TFT_1(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/tft', data=json.dumps(self.__class__.tft_template1), headers=headers)
        self.__class__.tft_template1 = r.json()
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_B_create_TFT_2(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/tft', data=json.dumps(self.__class__.tft_template2), headers=headers)
        self.__class__.tft_id = r.json()['tft_id']
        self.__class__.tft_template2 = r.json()
        log.debug("Created TFT ID " + str(self.__class__.tft_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_C_Get_TFT(self):
        r = requests.get(str(base_url) + '/tft/' + str(self.__class__.tft_id))
        self.assertEqual(self.__class__.tft_template2, r.json(), "JSON body should match input")

    def test_D_Patch_TFT(self):
        headers = {"Content-Type": "application/json"}
        patch_tft_template2 = self.__class__.tft_template2
        patch_tft_template2['tft_string'] = 'permit out ip from 10.98.0.20 80 to any 1-65535'
        patch_tft_template2['tft_id'] = self.__class__.tft_id
        r = requests.patch(str(base_url) + '/tft/' + str(self.__class__.tft_id), data=json.dumps(patch_tft_template2), headers=headers)
        self.assertEqual(patch_tft_template2, r.json(), "JSON body should match input")

    def test_E_Get_Patched_TFT(self):
        r = requests.get(str(base_url) + '/tft/' + str(self.__class__.tft_id))
        #Add TFT ID into Template for Validating
        patch_tft_template2 = self.__class__.tft_template2
        patch_tft_template2['tft_string'] = 'permit out ip from 10.98.0.20 80 to any 1-65535'
        patch_tft_template2['tft_id'] = self.__class__.tft_id
        self.assertEqual(patch_tft_template2, r.json(), "JSON body should match input")

    def test_F_create_Charging_Rule(self):
        headers = {"Content-Type": "application/json"}
        r = requests.put(str(base_url) + '/charging_rule', data=json.dumps(self.__class__.charging_rule_template), headers=headers)
        self.__class__.charging_rule_id = r.json()['charging_rule_id']
        log.debug("Created charging_rule_id " + str(self.__class__.charging_rule_id))
        self.assertEqual(r.status_code, 200, "Status Code should be 200 OK")

    def test_G_Get_Charging_Rule(self):
        r = requests.get(str(base_url) + '/charging_rule/' + str(self.__class__.charging_rule_id))
        #Add TFT ID into Template for Validating
        charging_rule_template = self.__class__.charging_rule_template
        charging_rule_template['charging_rule_id'] = self.__class__.charging_rule_id
        self.assertEqual(charging_rule_template, r.json(), "JSON body should match input")

    def test_H_Patch_Charging_Rule(self):
        headers = {"Content-Type": "application/json"}
        patch_charging_rule_template = self.__class__.charging_rule_template
        patch_charging_rule_template['rule_name'] = 'updated-via-api'
        patch_charging_rule_template['charging_rule_id'] = self.__class__.charging_rule_id
        r = requests.patch(str(base_url) + '/charging_rule/' + str(self.__class__.charging_rule_id), data=json.dumps(patch_charging_rule_template), headers=headers)
        self.assertEqual(patch_charging_rule_template, r.json(), "JSON body should match input")

    def test_I_Get_Patched_Charging_Rule(self):
        r = requests.get(str(base_url) + '/charging_rule/' + str(self.__class__.charging_rule_id))
        #Add charging_rule_id into Template for Validating
        patch_charging_rule_template = self.__class__.charging_rule_template
        patch_charging_rule_template['rule_name'] = 'updated-via-api'
        patch_charging_rule_template['charging_rule_id'] = self.__class__.charging_rule_id
        self.assertEqual(patch_charging_rule_template, r.json(), "JSON body should match input")

    def test_J_Get_Full_Charging_Rule(self):
        r = requests.get(str(base_url) + '/PCRF/' + str(self.__class__.charging_rule_id))
        #Add charging_rule_id into Template for Validating
        patch_charging_rule_template = self.__class__.charging_rule_template
        patch_charging_rule_template['rule_name'] = 'updated-via-api'
        patch_charging_rule_template['charging_rule_id'] = self.__class__.charging_rule_id
        patch_charging_rule_template['tft'] = []
        patch_charging_rule_template['tft'].append(self.__class__.tft_template1)
        patch_charging_rule_template['tft'].append(self.__class__.tft_template2)
        self.assertEqual(patch_charging_rule_template, r.json(), "JSON body should match input")


    def test_X_Delete_TFT2(self):
        r = requests.delete(str(base_url) + '/tft/' + str(self.__class__.tft_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

    def test_Y_Delete_TFT2(self):
        r = requests.delete(str(base_url) + '/tft/' + str(self.__class__.tft_id-1))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

    def test_Z_Delete_Charging_Rule(self):
        r = requests.delete(str(base_url) + '/charging_rule/' + str(self.__class__.charging_rule_id))
        xres = {"Result": "OK"}
        self.assertEqual(xres, r.json(), "JSON body should match " + str(xres))

if __name__ == '__main__':
    logging.basicConfig( stream=sys.stderr )
    logging.getLogger("UnitTestLogger").setLevel( logging.DEBUG )
    unittest.main()