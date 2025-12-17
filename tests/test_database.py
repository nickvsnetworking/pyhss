# Copyright 2021-2022 Nick <nick@nickvsnetworking.com>
# Copyright 2023 David Kneipp <david@davidkneipp.com>
# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import binascii
import os
import pprint

from database import (
    APN,
    AUC,
    CHARGING_RULE,
    Database,
    EIR,
    IMS_SUBSCRIBER,
    SUBSCRIBER,
    TFT,
)
from logtool import LogTool
from pyhss_config import config


def test_database(create_test_db):
    DeleteAfter = True
    database = Database(LogTool(config))

    # Define Charging Rule
    charging_rule = {
        "rule_name": "charging_rule_A",
        "qci": 4,
        "arp_priority": 5,
        "arp_preemption_capability": True,
        "arp_preemption_vulnerability": False,
        "mbr_dl": 128000,
        "mbr_ul": 128000,
        "gbr_dl": 128000,
        "gbr_ul": 128000,
        "tft_group_id": 1,
        "precedence": 100,
        "rating_group": 20000,
    }
    print("Creating Charging Rule A")
    ChargingRule_newObj_A = database.CreateObj(CHARGING_RULE, charging_rule)
    print("ChargingRule_newObj A: " + str(ChargingRule_newObj_A))
    charging_rule["gbr_ul"] = 256000
    charging_rule["gbr_dl"] = 256000
    charging_rule["mbr_ul"] = 256000
    charging_rule["mbr_dl"] = 256000
    print("Creating Charging Rule B")
    charging_rule["rule_name"], charging_rule["precedence"], charging_rule["tft_group_id"] = "charging_rule_B", 80, 2
    ChargingRule_newObj_B = database.CreateObj(CHARGING_RULE, charging_rule)
    print("ChargingRule_newObj B: " + str(ChargingRule_newObj_B))

    # Define TFTs
    tft_template1 = {"tft_group_id": 1, "tft_string": "permit out ip from any to any", "direction": 1}
    tft_template2 = {"tft_group_id": 1, "tft_string": "permit out ip from any to any", "direction": 2}
    print("Creating TFT")
    database.CreateObj(TFT, tft_template1)
    database.CreateObj(TFT, tft_template2)

    tft_template3 = {
        "tft_group_id": 2,
        "tft_string": "permit out ip from 10.98.0.0 255.255.255.0 to any",
        "direction": 1,
    }
    tft_template4 = {
        "tft_group_id": 2,
        "tft_string": "permit out ip from any to 10.98.0.0 255.255.255.0",
        "direction": 2,
    }
    print("Creating TFT")
    database.CreateObj(TFT, tft_template3)
    database.CreateObj(TFT, tft_template4)

    apn2 = {
        "apn": "ims",
        "apn_ambr_dl": 9999,
        "apn_ambr_ul": 9999,
        "arp_priority": 1,
        "arp_preemption_capability": False,
        "arp_preemption_vulnerability": True,
        "charging_rule_list": str(ChargingRule_newObj_A["charging_rule_id"])
        + ","
        + str(ChargingRule_newObj_B["charging_rule_id"]),
    }
    print("Creating APN " + str(apn2["apn"]))
    newObj = database.CreateObj(APN, apn2)
    print(newObj)

    print("Getting APN " + str(apn2["apn"]))
    print(database.GetObj(APN, newObj["apn_id"]))
    apn_id = newObj["apn_id"]
    UpdatedObj = newObj
    UpdatedObj["apn"] = "UpdatedInUnitTest"

    print("Updating APN " + str(apn2["apn"]))
    newObj = database.UpdateObj(APN, UpdatedObj, newObj["apn_id"])
    print(newObj)

    # Create AuC
    auc_json = {
        "ki": bytes.hex(os.urandom(16)).zfill(16),
        "opc": bytes.hex(os.urandom(16)).zfill(16),
        "amf": "9000",
        "sqn": 0,
    }
    print(auc_json)
    print("Creating AuC entry")
    newObj = database.CreateObj(AUC, auc_json)
    print(newObj)

    # Get AuC
    print("Getting AuC entry")
    newObj = database.GetObj(AUC, newObj["auc_id"])
    auc_id = newObj["auc_id"]
    print(newObj)

    # Update AuC
    print("Updating AuC entry")
    newObj["sqn"] = newObj["sqn"] + 10
    newObj = database.UpdateObj(AUC, newObj, auc_id)

    # Generate Vectors
    print("Generating Vectors")
    database.Get_Vectors_AuC(auc_id, "air", plmn="12ff")
    print(database.Get_Vectors_AuC(auc_id, "sip_auth", plmn="12ff"))

    # Update AuC
    database.Update_AuC(auc_id, sqn=100)

    # New Subscriber
    subscriber_json = {
        "imsi": "001001000000006",
        "enabled": True,
        "msisdn": "12345678",
        "ue_ambr_dl": 999999,
        "ue_ambr_ul": 999999,
        "nam": 0,
        "subscribed_rau_tau_timer": 600,
        "auc_id": auc_id,
        "default_apn": apn_id,
        "apn_list": apn_id,
    }

    # Delete IMSI if already exists
    try:
        existing_sub_data = database.Get_Subscriber(imsi=subscriber_json["imsi"])
        database.DeleteObj(SUBSCRIBER, existing_sub_data["subscriber_id"])
    except:
        print("Did not find old sub to delete")

    print("Creating new Subscriber")
    print(subscriber_json)
    newObj = database.CreateObj(SUBSCRIBER, subscriber_json)
    print(newObj)
    subscriber_id = newObj["subscriber_id"]

    # Get SUBSCRIBER
    print("Getting Subscriber")
    newObj = database.GetObj(SUBSCRIBER, subscriber_id)
    print(newObj)

    # Update SUBSCRIBER
    print("Updating Subscriber")
    newObj["ue_ambr_ul"] = 999995
    newObj = database.UpdateObj(SUBSCRIBER, newObj, subscriber_id)

    # Set MME Location for Subscriber
    print("Updating Serving MME for Subscriber")
    database.Update_Serving_MME(
        imsi=newObj["imsi"], serving_mme="Test123", serving_mme_peer="Test123", serving_mme_realm="TestRealm"
    )

    # Update Serving APN for Subscriber
    print("Updating Serving APN for Subscriber")
    database.Update_Serving_APN(
        imsi=newObj["imsi"],
        apn=apn2["apn"],
        pcrf_session_id="kjsdlkjfd",
        serving_pgw="pgw.test.com",
        subscriber_routing="1.2.3.4",
    )

    print("Getting Charging Rule for Subscriber / APN Combo")
    ChargingRule = database.Get_Charging_Rules(imsi=newObj["imsi"], apn=apn2["apn"])
    pprint.pprint(ChargingRule)

    # New IMS Subscriber
    ims_subscriber_json = {
        "msisdn": newObj["msisdn"],
        "msisdn_list": newObj["msisdn"],
        "imsi": subscriber_json["imsi"],
        "ifc_path": "default_ifc.xml",
    }
    print(ims_subscriber_json)
    newObj = database.CreateObj(IMS_SUBSCRIBER, ims_subscriber_json)
    print(newObj)
    ims_subscriber_id = newObj["ims_subscriber_id"]

    # Test Get Subscriber
    print("Test Getting Subscriber")
    GetSubscriber_Result = database.Get_Subscriber(imsi=subscriber_json["imsi"])
    print(GetSubscriber_Result)

    # Test IMS Get Subscriber
    print("Getting IMS Subscribers")
    print(database.Get_IMS_Subscriber(imsi="001001000000006"))
    print(database.Get_IMS_Subscriber(msisdn="12345678"))

    # Set SCSCF for Subscriber
    database.Update_Serving_CSCF(newObj["imsi"], "NickTestCSCF")
    # Get Served Subscriber List
    print(database.Get_Served_IMS_Subscribers())

    # Clear Serving PGW for PCRF Subscriber
    print("Clear Serving PGW for PCRF Subscriber")
    database.Update_Serving_APN(
        imsi=newObj["imsi"], apn=apn2["apn"], pcrf_session_id="sessionid123", serving_pgw=None, subscriber_routing=None
    )

    # Clear MME Location for Subscriber
    print("Clear MME Location for Subscriber")
    database.Update_Serving_MME(newObj["imsi"], None)

    # Generate Vectors for IMS Subscriber
    print("Generating Vectors for IMS Subscriber")
    print(database.Get_Vectors_AuC(auc_id, "sip_auth", plmn="12ff"))

    # print("Generating Resync for IMS Subscriber")
    # print(Get_Vectors_AuC(auc_id, "sqn_resync", auts='7964347dfdfe432289522183fcfb', rand='1bc9f096002d3716c65e4e1f4c1c0d17'))

    # Test getting APNs
    GetAPN_Result = database.Get_APN(GetSubscriber_Result["default_apn"])
    print(GetAPN_Result)

    # handleGeored({"imsi": "001001000000006", "serving_mme": "abc123"})

    if DeleteAfter == True:
        # Delete IMS Subscriber
        print(database.DeleteObj(IMS_SUBSCRIBER, ims_subscriber_id))
        # Delete Subscriber
        print(database.DeleteObj(SUBSCRIBER, subscriber_id))
        # Delete AuC
        print(database.DeleteObj(AUC, auc_id))
        # Delete APN
        print(database.DeleteObj(APN, apn_id))

    # Whitelist IMEI / IMSI Binding
    eir_template = {"imei": "1234", "imsi": "567", "regex_mode": 0, "match_response_code": 0}
    database.CreateObj(EIR, eir_template)

    # Blacklist Example
    eir_template = {"imei": "99881232", "imsi": "", "regex_mode": 0, "match_response_code": 1}
    database.CreateObj(EIR, eir_template)

    # IMEI Prefix Regex Example (Blacklist all IMEIs starting with 666)
    eir_template = {"imei": "^666.*", "imsi": "", "regex_mode": 1, "match_response_code": 1}
    database.CreateObj(EIR, eir_template)

    # IMEI Prefix Regex Example (Greylist response for IMEI starting with 777 and IMSI is 1234123412341234)
    eir_template = {"imei": "^777.*", "imsi": "^1234123412341234$", "regex_mode": 1, "match_response_code": 2}
    database.CreateObj(EIR, eir_template)

    print("\n\n\n\n")
    # Check Whitelist (No Match)
    assert database.Check_EIR(imei="1234", imsi="") == 2

    print("\n\n\n\n")
    # Check Whitelist (Matched)
    assert database.Check_EIR(imei="1234", imsi="567") == 0

    print("\n\n\n\n")
    # Check Blacklist (Match)
    assert database.Check_EIR(imei="99881232", imsi="567") == 1

    print("\n\n\n\n")
    # IMEI Prefix Regex Example (Greylist response for IMEI starting with 777 and IMSI is 1234123412341234)
    assert database.Check_EIR(imei="7771234", imsi="1234123412341234") == 2

    print(database.Get_IMEI_IMSI_History("1234123412"))

    print("\n\n\n")
    print(database.Generate_JSON_Model_for_Flask(SUBSCRIBER))
