#Example subscriber added to MongoDB directly

import sys
sys.path.append("..")

import yaml
import mongo
import pymongo
with open("../mongodb.yaml", 'r') as stream:
    mongo_conf = (yaml.safe_load(stream))

#Check if MongoDB in use
if type(mongo_conf) == dict and "mongodb_server" in mongo_conf and "mongodb_username" in mongo_conf and "mongodb_password" in mongo_conf and "mongodb_port" in mongo_conf:
    print("MongoDB configured to use server: " + str(mongo_conf['mongodb_server']))
    #Search for user in MongoDB database
    try:
        myclient = pymongo.MongoClient("mongodb://" + str(mongo_conf['mongodb_server']) + ":" + str(mongo_conf['mongodb_port']) + "/")
        mydb = myclient["open5gs"]
        mycol = mydb["subscribers"]
    except:
        print("Error connecting to database")
    
    pdn = [{'apn': 'internet', 'pcc_rule': [], 'ambr': {'downlink': 1234, 'uplink': 1234}, 'qos': {'qci': 9, 'arp': {'priority_level': 8, 'pre_emption_vulnerability': 1, 'pre_emption_capability': 1}}, 'type': 2}]
    sub_data = {'imsi': '891012222222300', \
                 'pdn': pdn, \
                 'ambr': {'downlink': 1024000, 'uplink': 1024001}, \
                 'subscribed_rau_tau_timer': 12, \
                 'network_access_mode': 2, \
                 'subscriber_status': 0, \
                 'access_restriction_data': 32, \
                 'security': {'k': '465B5CE8 B199B49F AA5F0A2E E238A6BC', 'amf': '8000', 'op': 'E8ED289D EBA952E4 283B54E8 8E6183CA', 'sqn': 1, 'opc': None}, '__v': 0}

    x = mycol.insert_one(sub_data)
    print("Added subscriber with Inserted ID : " + str(x.inserted_id))
else:
    print("Failed to get config data from YAML file")
##
##    imsi = "891012222222300"
##    myclient = pymongo.MongoClient("mongodb://" + str(mongo_conf['mongodb_server']) + ":" + str(mongo_conf['mongodb_port']) + "/")
##    mydb = myclient["open5gs"]
##    mycol = mydb["subscribers"]
##    myquery = { "imsi": str(imsi)}
##    print("Querying MongoDB for subscriber")
##    mydoc = mycol.find(myquery)
##    for x in mydoc:
##        print(x)
##
##    mycol.find_one_and_update(
##        {'imsi': str(imsi)},
##        {'$inc': {'security.sqn': 1}}
##    )
