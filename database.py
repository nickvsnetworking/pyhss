##PyHSS Database Library
##Features classes for different DB backends normalised to each return the same data
##Data is always provided by the function as a Dictionary of the Subscriber's data
import yaml
import logging
import threading
import os
import sys
sys.path.append(os.path.realpath('lib'))
import S6a_crypt

with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

import logtool
logtool = logtool.LogTool()
logtool.setup_logger('DBLogger', yaml_config['logging']['logfiles']['database_logging_file'], level=yaml_config['logging']['level'])
DBLogger = logging.getLogger('DBLogger')


DBLogger.info("DB Log Initialised.")

##Data Output Format
###Get Subscriber Info
#Outputs a dictionary with the format:
#subscriber_details = {'K': '465B5CE8B199B49FAA5F0A2EE238A6BC', 'OPc': 'E8ED289DEBA952E4283B54E88E6183CA', 'AMF': '8000', 'RAND': '', 'SQN': 22, \
# 'APN_list': 'internet', 'pdn': [{'apn': 'internet', '_id': ObjectId('5fe2815ce601d905f8c597b3'), 'pcc_rule': [], 'qos': {'qci': 9, 'arp': {'priority_level': 8, 'pre_emption_vulnerability': 1, 'pre_emption_capability': 1}}, 'type': 2}]}


class MongoDB:
    import mongo
    import pymongo
    def __init__(self):
        DBLogger.info("Configured to use MongoDB server: " + str(yaml_config['database']['mongodb']['mongodb_server']))
        self.server = {}
        self.server['mongodb_server'] = yaml_config['database']['mongodb']['mongodb_server']
        self.server['mongodb_port'] = yaml_config['database']['mongodb']['mongodb_port']
        
    def QueryDB(self, imsi):
        #Search for user in MongoDB database
        myclient = self.pymongo.MongoClient("mongodb://" + str(self.server['mongodb_server']) + ":" + str(self.server['mongodb_port']) + "/")
        mydb = myclient["open5gs"]
        mycol = mydb["subscribers"]
        myquery = { "imsi": str(imsi)}
        DBLogger.debug("Querying MongoDB for subscriber " + str(imsi))
        return mycol.find(myquery)
        
    #Loads a subscriber's information from database into dict for referencing
    def GetSubscriberInfo(self, imsi):
        subscriber_details = {}
  
        try:
            mydoc = self.QueryDB(imsi)
        except:
            DBLogger.debug("Failed to pull subscriber info")
            raise ValueError("Failed to pull subscriber details for IMSI " + str(imsi) + " from MongoDB")

        #If query was completed Successfully extract data
        for x in mydoc:
            DBLogger.debug("Got result from MongoDB")
            DBLogger.debug(x)
            subscriber_details['K'] = x['security']['k'].replace(' ', '')
            try:
                subscriber_details['OP'] = x['security']['op'].replace(' ', '')
                DBLogger.debug("Database has OP stored - Converting to OPc")
                ##Convert to OPc
                subscriber_details['OPc'] = S6a_crypt.generate_opc(subscriber_details['K'], subscriber_details['OP'])
                #Remove OP reference from dict
                subscriber_details.pop('OP', None)
            except:
                subscriber_details['OPc'] = x['security']['opc'].replace(' ', '')
            subscriber_details['AMF'] = x['security']['amf'].replace(' ', '')
            try:
                subscriber_details['RAND'] = x['security']['rand'].replace(' ', '')
                subscriber_details['SQN'] = int(x['security']['sqn'])
            except:
                DBLogger.debug("Subscriber " + str() + " has not attached before - Generating new SQN and RAND")
                subscriber_details['SQN'] = 1
                subscriber_details['RAND'] = ''
            apn_list = ''
            for keys in x['slice'][0]['session']:
                apn_list += keys['name'] + ";"
            subscriber_details['APN_list'] = apn_list[:-1]      #Remove last semicolon
            DBLogger.debug("APN list is: " + str(subscriber_details['APN_list']))
            subscriber_details['pdn'] = x['slice'][0]['session']
            i = 0
            while i < len(subscriber_details['pdn']):
                #Rename from "name" to "apn"
                subscriber_details['pdn'][i]['apn'] = subscriber_details['pdn'][i]['name']
                #Store QCI data
                subscriber_details['pdn'][i]['qos']['qci'] = subscriber_details['pdn'][i]['qos']['index']
                #Map static P-GW Address
                if 'smf' in subscriber_details['pdn'][i]:
                    subscriber_details['pdn'][i]['ue'] = {}
                    subscriber_details['pdn'][i]['ue']['ip'] = subscriber_details['pdn'][i]['smf']['addr']
                i += 1
            DBLogger.debug(subscriber_details)
            return subscriber_details
        
        #if no results returned raise error
        raise ValueError("Mongodb has no matching subscriber details for IMSI " + str(imsi) + " from MongoDB")




    #Update a subscriber's information in MongoDB
    def UpdateSubscriber(self, imsi, sqn, rand, *args, **kwargs):
        DBLogger.debug("Updating " + str(imsi))
        
        #Check if MongoDB in use
        try:
            DBLogger.debug("Updating SQN for imsi " + str(imsi) + " to " + str(sqn))
            #Search for user in MongoDB database
            myclient = self.pymongo.MongoClient("mongodb://" + str(self.server['mongodb_server']) + ":" + str(self.server['mongodb_port']) + "/")
            mydb = myclient["open5gs"]
            mycol = mydb["subscribers"]
            myquery = { 'imsi': str(imsi) }
            newvalues = { "$set": {'security.rand': str(rand)} }
            mycol.update_one(myquery, newvalues)
            newvalues = { "$set": {'security.sqn': int(sqn)} }
            if 'origin_host' in kwargs:
                DBLogger.info("origin_host present - Storing location in DB")
                origin_host = kwargs.get('origin_host', None)
                newvalues = { "$set": {'origin_host': str(origin_host)} }
            mycol.update_one(myquery, newvalues)
            return sqn
        except:
            raise ValueError("Failed update SQN for subscriber " + str(imsi) + " in MongoDB")
        
    def GetSubscriberLocation(self, *args, **kwargs):
        DBLogger.debug("Called GetSubscriberLocation")
        if 'imsi' in kwargs:
            DBLogger.debug("IMSI present - Searching based on IMSI")
            try:
                imsi = kwargs.get('imsi', None)
                DBLogger.debug("GetSubscriberLocation IMSI is " + str(imsi))
                DBLogger.debug("Calling GetSubscriberLocation with IMSI " + str(imsi))
                mydoc = self.QueryDB(imsi)
                for x in mydoc:
                    DBLogger.debug(x)
                    try:
                        return x['origin_host']
                    except:
                        DBLogger.debug("No location stored for sub")
            except:
                DBLogger.debug("Failed to pull subscriber info")
                raise ValueError("Failed to pull subscriber details for IMSI " + str(imsi) + " from MongoDB")
     
        elif 'msisdn' in kwargs:
            DBLogger.debug("MSISDN present - Searching based on MSISDN ")
            try:
                msisdn = kwargs.get('msisdn', None)
                DBLogger.debug("msisdn is " + str(msisdn))
                DBLogger.debug("Calling GetSubscriberLocation with msisdn " + str(msisdn))
                mydoc = self.QueryDB(msisdn)
                for x in mydoc:
                    DBLogger.debug(x)
                    try:
                        return x['origin_host']
                    except:
                        DBLogger.debug("No location stored for sub")
            except:
                DBLogger.debug("Failed to pull subscriber info")
                raise ValueError("Failed to pull subscriber details for IMSI " + str(imsi) + " from MongoDB")

class MSSQL:
    import _mssql
    def __init__(self):
        DBLogger.info("Configured to use MS-SQL server: " + str(yaml_config['database']['mssql']['server']))
        self.server = yaml_config['database']['mssql']
        self._lock = threading.Lock()
        try:
            self.conn = self._mssql.connect(server=self.server['server'], user=self.server['username'], password=self.server['password'], database=self.server['database'])
            DBLogger.info("Connected to MSSQL Server")
        except:
            #If failed to connect to server
            DBLogger.fatal("Failed to connect to MSSQL server at " + str(self.server['server']))
            raise OSError("Failed to connect to MSSQL server at " + str(self.server['server']))
            sys.exit()

    def reset(self):
        DBLogger.info("Reinitializing / Instantiating DB Class")
        self.__init__()

    def GetSubscriberInfo(self, imsi):
        with self._lock:
            try:
                DBLogger.debug("Getting subscriber info from MSSQL for IMSI " + str(imsi))
                subscriber_details = {}
                sql = "hss_imsi_known_check @imsi=" + str(imsi)
                DBLogger.debug(sql)
                self.conn.execute_query(sql)
                DBLogger.debug("Ran hss_imsi_known_check OK - Checking results")
                DBLogger.debug("Parsing results to var")
                result = [ row for row in self.conn ]
                DBLogger.debug("Result total is " + str(result))
                DBLogger.debug("Getting first entry in result")
                result = result[0]
                DBLogger.debug("printing final result:")
                DBLogger.debug(str(result))
            except Exception as e:
                DBLogger.error("failed to run " + str(sql))
                DBLogger.error(e)
                logtool.RedisIncrimenter('AIR_hss_imsi_known_check_SQL_Fail')
                raise Exception("Failed to query MSSQL server with query: " + str(sql))

            try:
                #known_imsi: IMSI attached with sim returns 1 else returns 0
                if str(result['known_imsi']) != '1':
                    logtool.RedisIncrimenter('AIR_hss_imsi_known_check_IMSI_unattached_w_SIM')
                    raise ValueError("MSSQL reports IMSI " + str(imsi) + " not attached with SIM")

                #subscriber_status: -1 –Blocked or 0-Active
                if str(result['subscriber_status']) != '0':
                    logtool.RedisIncrimenter('AIR_hss_imsi_known_check_IMSI_Blocked')
                    raise ValueError("MSSQL reports Subscriber Blocked for IMSI " + str(imsi))

                apn_id = result['apn_configuration']


                DBLogger.debug("Running hss_get_subscriber_data_v2 for imsi " + str(imsi))
                sql = 'hss_get_subscriber_data_v2 @imsi="' + str(imsi) + '";'
                DBLogger.debug("SQL: " + str(sql))
                self.conn.execute_query(sql)
                result = [ row for row in self.conn ][0]

                DBLogger.debug("\nResult of hss_get_subscriber_data_v2_v2: " + str(result))
                #subscriber_status: -1 –Blocked or 0-Active (Again)
                if str(result['subscriber_status']) != '0':
                    logtool.RedisIncrimenter('AIR_hss_get_subscriber_data_v2_v2_IMSI_Blocked')
                    raise ValueError("MSSQL reports Subscriber Blocked for IMSI " + str(imsi))
                
                #Get data output and put it into structure PyHSS uses
                subscriber_details['RAT_freq_priorityID'] = result['RAT_freq_priorityID']
                subscriber_details['APN_OI_replacement'] = result['APN_OI_replacement']
                subscriber_details['3gpp_charging_ch'] = result['_3gpp_charging_ch']
                subscriber_details['ue_ambr_ul'] = result['MAX_REQUESTED_BANDWIDTH_UL']
                subscriber_details['ue_ambr_dl'] = result['MAX_REQUESTED_BANDWIDTH_DL']
                subscriber_details['K'] = result['ki']
                subscriber_details['SQN'] = result['seqno']
                subscriber_details['RAT_freq_priorityID'] = result['RAT_freq_priorityID']
                subscriber_details['3gpp-charging-characteristics'] = result['_3gpp_charging_ch']
                
                #Harcoding AMF as it is the same for all SIMs and not returned by DB
                subscriber_details['AMF'] = '8000'

                #Set dummy RAND value (No need to store it)
                subscriber_details['RAND'] = ""

                #Format MSISDN
                subscriber_details['msisdn'] = str(result['region_subscriber_zone_code']) + str(result['msisdn'])
                subscriber_details['msisdn'] = subscriber_details['msisdn'].split(';')[-1]
                subscriber_details['a-msisdn'] = str(result['msisdn'])

                #Convert OP to OPc
                subscriber_details['OP'] = result['op_key']
                DBLogger.debug("Generating OPc with input K: " + str(subscriber_details['K']) + " and OP: " + str(subscriber_details['OP']))
                subscriber_details['OPc'] = S6a_crypt.generate_opc(subscriber_details['K'], subscriber_details['OP'])
                subscriber_details.pop('OP', None)
                DBLogger.debug("Generated OPc " + str(subscriber_details['OPc']))


                DBLogger.debug("Getting APN info")
                sql = 'hss_get_apn_info @apn_profileId=' + str(apn_id)
                DBLogger.debug(sql)
                self.conn.execute_query(sql)
                DBLogger.debug("Ran query")
                subscriber_details['pdn'] = []
                DBLogger.debug("Parsing results to var")
                result = [ row for row in self.conn ][0]
                DBLogger.debug("Got results")
                DBLogger.debug("Results are: " + str(result))
                apn = {'apn': str(result['Service_Selection']),\
                        'pcc_rule': [], 'qos': {'qci': int(result['QOS_CLASS_IDENTIFIER']), \
                        'arp': {'priority_level': int(result['QOS_PRIORITY_LEVEL']), 'pre_emption_vulnerability': int(result['QOS_PRE_EMP_VULNERABILITY']), 'pre_emption_capability': int(result['QOS_PRE_EMP_CAPABILITY'])}},\
                        'ambr' : {'apn_ambr_ul' : int(result['MAX_REQUESTED_BANDWIDTH_UL']), 'apn_ambr_Dl' : int(result['MAX_REQUESTED_BANDWIDTH_DL'])},
                        'PDN_GW_Allocation_Type' : int(result['PDN_GW_Allocation_Type']),
                        'VPLMN_Dynamic_Address_Allowed' : int(result['VPLMN_Dynamic_Address_Allowed']),
                        'type': 2, 'MIP6-Agent-Info' : {'MIP6_DESTINATION_HOST' : result['MIP6_DESTINATION_HOST'], 'MIP6_DESTINATION_REALM' : result['MIP6_DESTINATION_REALM']}}
                subscriber_details['pdn'].append(apn)

                DBLogger.debug("Final subscriber data for IMSI " + str(imsi) + " is: " + str(subscriber_details))
                return subscriber_details
            except Exception as e:
                logtool.RedisIncrimenter('AIR_general')
                DBLogger.error("General MSSQL Error")
                DBLogger.error(e)
                raise ValueError("MSSQL failed to return valid data for IMSI " + str(imsi))   
                

    def GetSubscriberLocation(self, *args, **kwargs):
        with self._lock:
            DBLogger.debug("Called GetSubscriberLocation")
            if 'imsi' in kwargs:
                DBLogger.debug("IMSI present - Searching based on IMSI")
                try:
                    imsi = kwargs.get('imsi', None)
                    DBLogger.debug("Calling hss_get_mme_identity_by_info with IMSI " + str(imsi))
                    sql = 'hss_get_mme_identity_by_info ' + str(imsi) + ';'
                    DBLogger.info(sql)
                    self.conn.execute_query(sql)
                    DBLogger.debug(self.conn)
                except Exception as e:
                    DBLogger.error("failed to run " + str(sql))
                    DBLogger.error(e)
                    raise ValueError("MSSQL failed to run SP hss_get_mme_identity_by_info for IMSI " + str(imsi))     
            elif 'msisdn' in kwargs:
                DBLogger.debug("MSISDN present - Searching based on MSISDN")
                try:
                    msisdn = kwargs.get('msisdn', None)
                    DBLogger.debug("Calling hss_get_mme_identity_by_info with msisdn " + str(msisdn))
                    sql = 'hss_get_mme_identity_by_info ' + str(msisdn) + ';'
                    self.conn.execute_query(sql)
                    DBLogger.debug(self.conn)
                except:
                    DBLogger.critical("MSSQL failed to run SP hss_get_mme_identity_by_info for msisdn " + str(msisdn))
                    raise ValueError("MSSQL failed to run SP hss_get_mme_identity_by_info for msisdn " + str(msisdn)) 
                    
            else:
                raise ValueError("No IMSI or MSISDN provided - Aborting")
            
            try:
                DBLogger.debug(self.conn)
                result = [ row for row in self.conn ][0]
                DBLogger.debug("Returned data:")
                DBLogger.debug(result)
                DBLogger.debug("Stripping to only include Origin_Host")
                result = result['Origin_Host']
                DBLogger.debug("Final result is: " + str(result))
                return result
            except:
                DBLogger.debug("No location stored in database for Subscriber")
                raise ValueError("No location stored in database for Subscriber")

    def UpdateSubscriber(self, imsi, sqn, rand, *args, **kwargs):
        with self._lock:
            try:
                DBLogger.debug("Updating SQN for imsi " + str(imsi) + " to " + str(sqn))
                try:
                    DBLogger.debug("Updating SQN using SP hss_auth_get_ki_v2")
                    sql = 'hss_auth_get_ki_v2 @imsi=' + str(imsi) + ', @NBofSeq=' + str(sqn) + ';'
                    DBLogger.debug(sql)
                    self.conn.execute_query(sql)
                    DBLogger.debug(self.conn)
                except Exception as e:
                    DBLogger.error("MSSQL failed to run SP hss_auth_get_ki_v2 with SQN " + str(sqn) + " for IMSI " + str(imsi))  
                    DBLogger.error(e)
                    raise ValueError("MSSQL failed to run SP hss_auth_get_ki_v2 with SQN " + str(sqn) + " for IMSI " + str(imsi))  

                #If optional origin_host kwag present, store UE location (Serving MME) in Database
                if 'origin_host' in kwargs:
                    DBLogger.debug("origin_host present - Updating MME Identity of subscriber in MSSQL")
                    origin_host = kwargs.get('origin_host', None)
                    DBLogger.debug("Origin to write to DB is " + str(origin_host))
                    if len(origin_host) != 0:
                        try:
                            DBLogger.debug("origin-host valid - Writing back to DB")
                            sql = 'hss_update_mme_identity @imsi=' + str(imsi) + ', @orgin_host=\'' + str(origin_host) + '\', @Cancellation_Type=0, @ue_purged_mme=0;'
                            DBLogger.debug(sql)
                            self.conn.execute_query(sql)
                            DBLogger.debug("Successfully updated location for " + str(imsi))
                        except:
                            DBLogger.error("MSSQL failed to run SP hss_update_mme_identity with IMSI " + str(imsi) + " and Origin_Host " + str(origin_host))
                    else:
                        try:
                            DBLogger.debug("Removing MME Identity as new MME Identity is empty")
                            sql = 'hss_delete_mme_identity @imsi=' + str(imsi) 
                            DBLogger.debug(sql)
                            self.conn.execute_query(sql)
                            DBLogger.debug("Successfully cleared location for " + str(imsi))
                        except:
                            DBLogger.error("MSSQL failed to run SP hss_delete_mme_identity with IMSI " + str(imsi))
                else:
                    DBLogger.debug("origin_host not present - not updating UE location in database")

                if ('serving_hss' in kwargs) and ('serving_mme' in kwargs) and ('dra' in kwargs) :
                    DBLogger.debug("Storing full location")
                    serving_hss = kwargs.get('serving_hss', None)
                    serving_mme = kwargs.get('serving_mme', None)
                    dra = kwargs.get('dra', None)

                    DBLogger.debug("Full MME Location to write to DB, serving HSS: " + str(serving_hss) + ", serving_mme: " + str(serving_mme) + " connected via Diameter Peer " + str(dra))
                    try:
                        sql = 'hss_cancl_loc_imsi_insert_info @imsi=' + str(imsi) + ', @serving_hss=\'' + str(serving_hss) + '\', @serving_mme=\'' + str(serving_mme) + '\', @dra=\'' + str(dra) + '\';'
                        DBLogger.debug(sql)
                        self.conn.execute_query(sql)
                        DBLogger.debug("Successfully raun hss_cancl_loc_imsi_insert_info for " + str(imsi))
                    except:
                        DBLogger.error("MSSQL failed to run SP hss_cancl_loc_imsi_insert_info with IMSI " + str(imsi))

                else:
                    DBLogger.debug("Required parameters for full MME location storage not present - not updating UE location in database")
            except:
                raise ValueError("MSSQL failed to update IMSI " + str(imsi))   
        
    def GetSubscriberIMSI(self, msisdn):
        with self._lock:
            try:
                DBLogger.debug("Getting Subscriber IMSI from MSISDN" + str(msisdn))
                sql = 'hss_get_imsi_by_msisdn @msisdn=' + str(msisdn) + ';'
                DBLogger.debug(sql)
                self.conn.execute_query(sql)
                DBLogger.debug(self.conn)
            except Exception as e:
                DBLogger.error("MSSQL failed to run SP " + str(sql))  
                DBLogger.error(e)
                raise ValueError("MSSQL failed to run SP " + str(sql))  
        DBLogger.debug("Ran Query OK...")
        try:
            DBLogger.debug(self.conn)
            result = [ row for row in self.conn ][0]
            DBLogger.debug("Returned data:")
            DBLogger.debug(result)
            DBLogger.debug("Stripping to only include imsi")
            result = result['imsi']
            DBLogger.debug("Final result is: " + str(result))            
            DBLogger.debug(result)
            DBLogger.debug("Final result is: " + str(result))
            return result
        except:
            DBLogger.debug("IMSI for MSISDN Provided.")
            raise ValueError("IMSI for MSISDN Provided.")
class MySQL:
    import mysql.connector
    def __init__(self):
        DBLogger.info("Configured to use MySQL server: " + str(yaml_config['database']['mysql']['server']))
        self.server = yaml_config['database']['mysql']
        self.mydb = self.mysql.connector.connect(
          host=self.server['server'],
          user=self.server['username'],
          password=self.server['password'],
          database=self.server['database']
        )
        self.mydb.autocommit = True
        self.mydb.SQL_QUERYTIMEOUT = 3
        cursor = self.mydb.cursor(dictionary=True)
        self.cursor = cursor
        
    def GetSubscriberInfo(self, imsi):
        DBLogger.debug("Getting subscriber info from MySQL for IMSI " + str(imsi))
        self.cursor.execute("select * from subscribers left join subscriber_apns on subscribers.imsi = subscriber_apns.imsi left join apns on subscriber_apns.apn_id = apns.apn_id where subscribers.imsi = " + str(imsi))
        subscriber_details = self.cursor.fetchall()
        return subscriber_details

    def UpdateSubscriber(self, imsi, sqn, rand, *args, **kwargs):
        DBLogger.debug("Updating SQN for imsi " + str(imsi) + " to " + str(sqn))
        query = 'update subscribers set sqn = ' + str(sqn) + ' where imsi = ' + str(imsi)
        DBLogger.debug(query)
        self.cursor.execute(query)
        
            
#Load DB functions based on Config
for db_option in yaml_config['database']:
    DBLogger.debug("Selected DB backend " + str(db_option))
    break

if db_option == "mongodb":
    DB = MongoDB()
elif db_option == "mssql":
    DB = MSSQL()
elif db_option == "mysql":
    DB = MySQL()
else:
    DBLogger.fatal("Failed to find any compatible database backends. Please ensure the database type you have in the config.yaml file corresponds to a database type defined in database.py Exiting.")
    sys.exit()

def GetSubscriberInfo(imsi):
    return DB.GetSubscriberInfo(imsi)

def UpdateSubscriber(imsi, sqn, rand, *args, **kwargs):
    if 'origin_host' in kwargs:
        DBLogger.debug("UpdateSubscriber called with origin_host present")
        origin_host = kwargs.get('origin_host', None)
        DBLogger.debug("Origin Host: " + str(origin_host))
        return DB.UpdateSubscriber(imsi, sqn, rand, origin_host=str(origin_host))
    else:
        return DB.UpdateSubscriber(imsi, sqn, rand)

def GetSubscriberLocation(*args, **kwargs):
    #Input can be either MSISDN or IMSI
    if 'imsi' in kwargs:
        DBLogger.info("Called GetSubscriberLocation with IMSI")
        imsi = kwargs.get('imsi', None)
        return DB.GetSubscriberLocation(imsi=imsi)
    elif 'msisdn' in kwargs:
        DBLogger.info("Called GetSubscriberLocation with MSISDN")
        msisdn = kwargs.get('msisdn', None)
        return DB.GetSubscriberLocation(msisdn=msisdn)

def Get_IMSI_from_MSISDN(msisdn):
    return DB.GetSubscriberIMSI(msisdn)

#Unit test if file called directly (instead of imported)
if __name__ == "__main__":
    test_sub_imsi = yaml_config['hss']['test_sub_imsi']
    DB.GetSubscriberInfo(test_sub_imsi)
    DB.UpdateSubscriber(test_sub_imsi, 998, '', origin_host='mme01.epc.mnc001.mcc01.3gppnetwork.org')
    origin_host = DB.GetSubscriberLocation(imsi=test_sub_imsi)
    print("Origin Host is " + str(origin_host))
    print(DB.GetSubscriberIMSI(34604610206))
    
