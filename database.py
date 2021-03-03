##PyHSS Database Library
##Features classes for different DB backends normalised to each return the same data
##Data is always provided by the function as a Dictionary of the Subscriber's data
import yaml
import logging
logging.basicConfig(level="DEBUG")
import os
import sys
sys.path.append(os.path.realpath('lib'))
import S6a_crypt

with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

##Data Output Format
###Get Subscriber Info
#Outputs a dictionary with the format:
#subscriber_details = {'K': '465B5CE8B199B49FAA5F0A2EE238A6BC', 'OPc': 'E8ED289DEBA952E4283B54E88E6183CA', 'AMF': '8000', 'RAND': '', 'SQN': 22, 'APN_list': 'internet', 'pdn': [{'apn': 'internet', '_id': ObjectId('5fe2815ce601d905f8c597b3'), 'pcc_rule': [], 'qos': {'qci': 9, 'arp': {'priority_level': 8, 'pre_emption_vulnerability': 1, 'pre_emption_capability': 1}}, 'type': 2}]}


class MongoDB:
    import mongo
    import pymongo
    def __init__(self):
        logging.info("Configured to use MongoDB server: " + str(yaml_config['database']['mongodb']['mongodb_server']))
        self.server = {}
        self.server['mongodb_server'] = yaml_config['database']['mongodb']['mongodb_server']
        self.server['mongodb_port'] = yaml_config['database']['mongodb']['mongodb_port']
        
    def QueryDB(self, imsi):
        #Search for user in MongoDB database
        myclient = self.pymongo.MongoClient("mongodb://" + str(self.server['mongodb_server']) + ":" + str(self.server['mongodb_port']) + "/")
        mydb = myclient["open5gs"]
        mycol = mydb["subscribers"]
        myquery = { "imsi": str(imsi)}
        logging.debug("Querying MongoDB for subscriber " + str(imsi))
        return mycol.find(myquery)
        
    #Loads a subscriber's information from database into dict for referencing
    def GetSubscriberInfo(self, imsi):
        subscriber_details = {}
  
        try:
            mydoc = self.QueryDB(imsi)
        except:
            logging.debug("Failed to pull subscriber info")
            raise ValueError("Failed to pull subscriber details for IMSI " + str(imsi) + " from MongoDB")

        #If query was completed sucesfully extract data
        for x in mydoc:
            logging.debug("Got result from MongoDB")
            subscriber_details['K'] = x['security']['k'].replace(' ', '')
            try:
                subscriber_details['OP'] = x['security']['op'].replace(' ', '')
                logging.debug("Database has OP stored - Converting to OPc")
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
                logging.debug("Subscriber " + str() + " has not attached before - Generating new SQN and RAND")
                subscriber_details['SQN'] = 1
                subscriber_details['RAND'] = ''
            apn_list = ''
            for keys in x['pdn']:
                apn_list += keys['apn'] + ";"
            subscriber_details['APN_list'] = apn_list[:-1]      #Remove last semicolon
            subscriber_details['pdn'] = x['pdn']                
            logging.debug(subscriber_details)
            return subscriber_details
        
        #if no results returned raise error
        raise ValueError("Mongodb has no matching subscriber details for IMSI " + str(imsi) + " from MongoDB")




    #Update a subscriber's information in MongoDB
    def UpdateSubscriber(self, imsi, sqn, rand):
        logging.debug("Updating " + str(imsi))
        
        #Check if MongoDB in use
        try:
            logging.debug("Updating SQN for imsi " + str(imsi) + " to " + str(sqn))
            #Search for user in MongoDB database
            myclient = self.pymongo.MongoClient("mongodb://" + str(self.server['mongodb_server']) + ":" + str(self.server['mongodb_port']) + "/")
            mydb = myclient["open5gs"]
            mycol = mydb["subscribers"]
            myquery = { 'imsi': str(imsi) }
            newvalues = { "$set": {'security.rand': str(rand)} }
            mycol.update_one(myquery, newvalues)
            newvalues = { "$set": {'security.sqn': int(sqn)} }
            mycol.update_one(myquery, newvalues)
            return sqn
        except:
            raise ValueError("Failed update SQN for subscriber " + str(imsi) + " in MongoDB")
        


class MSSQL:
    #import pymssql
    import _mssql
    def __init__(self):
        logging.info("Configured to use MS-SQL server: " + str(yaml_config['database']['mssql']['server']))
        self.server = yaml_config['database']['mssql']
        try:
            self.conn = self._mssql.connect(server=self.server['server'], user=self.server['username'], password=self.server['password'], database=self.server['database'])
            logging.info("Connected to MSSQL Server")
        except:
            #If failed to connect to server
            logging.fatal("Failed to connect to MSSQL server at " + str(self.server['server']))
            raise OSError("Failed to connect to MSSQL server at " + str(self.server['server']))
            sys.exit()



    def GetSubscriberInfo(self, imsi):
        try:
            logging.debug("Getting subscriber info from MSSQL for IMSI " + str(imsi))
            subscriber_details = {}
            #try:
            self.conn.execute_query('hss_imsi_known_check @imsi=' + str(imsi))
            result = [ row for row in self.conn ][0]
            print("\nResult of hss_imsi_known_check: " + str(result))

            #known_imsi: IMSI attached with sim returns 1 else returns 0
            if str(result['known_imsi']) != '1':
                raise ValueError("MSSQL reports IMSI " + str(imsi) + " not attached with SIM")

            #subscriber_status: -1 –Blocked or 0-Active
            if str(result['subscriber_status']) != '0':
                raise ValueError("MSSQL reports Subscriber Blocked for IMSI " + str(imsi))

            apn_id = result['apn_configuration']


            logging.debug("Running hss_get_subscriber_data for imsi " + str(imsi))
            self.conn.execute_query('hss_get_subscriber_data @imsi=' + str(imsi))
            result = [ row for row in self.conn ][0]
            print("\nResult of hss_get_subscriber_data: " + str(result))
            #subscriber_status: -1 –Blocked or 0-Active (Again)
            if str(result['subscriber_status']) != '0':
                raise ValueError("MSSQL reports Subscriber Blocked for IMSI " + str(imsi))
            
            subscriber_details['msisdn'] = result['msisdn']
            subscriber_details['RAT_freq_priorityID'] = result['RAT_freq_priorityID']
            subscriber_details['APN_OI_replacement'] = result['APN_OI_replacement']
            subscriber_details['APN_OI_replacement'] = result['APN_OI_replacement']
            subscriber_details['3gpp_charging_ch'] = result['_3gpp_charging_ch']
            subscriber_details['ue_ambr_ul'] = result['MAX_REQUESTED_BANDWIDTH_UL']
            subscriber_details['ue_ambr_dl'] = result['MAX_REQUESTED_BANDWIDTH_DL']
            subscriber_details['K'] = result['ki']
            subscriber_details['SQN'] = result['seqno']

            #Convert OP to OPc
            subscriber_details['OP'] = result['op_key']
            subscriber_details['OPc'] = S6a_crypt.generate_opc(subscriber_details['K'], subscriber_details['OP'])
            subscriber_details.pop('OP', None)

            self.conn.execute_query('hss_get_apn_info @apn_profileId=' + str(apn_id))
            subscriber_details['pdn'] = []
            for result in self.conn:
                print("\nResult of hss_get_apn_info: " + str(result))
                subscriber_details['pdn'].append({'apn': str(result['Service_Selection']),\
                    'pcc_rule': [], 'qos': {'qci': int(result['QOS_CLASS_IDENTIFIER']), \
                    'arp': {'priority_level': int(result['QOS_PRIORITY_LEVEL']), 'pre_emption_vulnerability': int(result['QOS_PRE_EMP_VULNERABILITY']), 'pre_emption_capability': int(result['QOS_PRE_EMP_CAPABILITY'])}},\
                    'type': 2})

            logging.debug("Final subscriber data for IMSI " + str(imsi) + " is: " + str(subscriber_details))
            return subscriber_details
        except:
            raise ValueError("MSSQL failed to return valid data for IMSI " + str(imsi))   
    
    def GetSubscriberLocation(self, *args, **kwargs):
        logging.debug("Called GetSubscriberLocation")
        if 'imsi' in kwargs:
            logging.debug("IMSI present - Searching based on IMSI")
            try:
                imsi = kwargs.get('imsi', None)
                logging.debug("Calling hss_get_mme_identity with IMSI " + str(imsi))
                self.conn.execute_query('hss_get_mme_identity @imsi=' + str(imsi) + ';')
                logging.debug(self.conn)
            except:
                raise ValueError("MSSQL failed to run SP hss_get_mme_identity for IMSI " + str(imsi))                  
        elif 'msisdn' in kwargs:
            logging.debug("MSISDN present - Searching based on MSISDN")
            try:
                msisdn = kwargs.get('msisdn', None)
                logging.debug("Calling hss_get_mme_identity with msisdn " + str(msisdn))
                self.conn.execute_query('hss_get_mme_identity @msisdn=' + str(msisdn) + ';')
                logging.debug(self.conn)
            except:
                raise ValueError("MSSQL failed to run SP hss_get_mme_identity for msisdn " + str(msisdn)) 
        else:
            raise ValueError("No IMSI or MSISDN provided - Aborting")
        
    def UpdateSubscriber(self, imsi, sqn, rand, *args, **kwargs):
        try:
            logging.debug("Updating SQN for imsi " + str(imsi) + " to " + str(sqn))
            try:
                logging.debug("Updating SQN using SP hss_auth_get_ki_v2")
                sql = 'hss_auth_get_ki_v2 @imsi=' + str(imsi) + ', @NBofSeq=' + str(sqn) + ';'
                logging.debug(sql)
                self.conn.execute_query(sql)
                logging.debug(self.conn)
            except:
                logging.error("MSSQL failed to run SP hss_auth_get_ki_v2 with SQN " + str(sqn) + " for IMSI " + str(imsi))  
                raise ValueError("MSSQL failed to run SP hss_auth_get_ki_v2 with SQN " + str(sqn) + " for IMSI " + str(imsi))  

            #If optional origin_host kwag present, store UE location (Serving MME) in Database
            if 'origin_host' in kwargs:
                logging.debug("origin_host present - Updating MME Identity of subscriber")
                logging.debug("Getting Origin-Host")
                origin_host = kwargs.get('origin_host', None)
                logging.debug("Origin Host: " + str(origin_host))

                if len(origin_host) != 0:
                    try:
                        logging.debug("Updating MME Identity using SP hss_update_mme_identity")
                        logging.debug("Writing serving MME to database")
                        sql = 'hss_update_mme_identity @imsi=' + str(imsi) + ', @orgin_host=\'' + str(origin_host) + '\', @Cancellation_Type=0, @ue_purged_mme=0;'
                        logging.debug(sql)
                        self.conn.execute_query(sql)
                    except:
                        logging.error("MSSQL failed to run SP hss_update_mme_identity with IMSI " + str(imsi) + " and Origin_Host " + str(origin_host))
                else:
                    try:
                        logging.debug("Removing MME Identity as new MME Identity is empty")
                        sql = 'hss_delete_mme_identity @imsi=' + str(imsi) 
                        logging.debug(sql)
                        self.conn.execute_query(sql)
                    except:
                        logging.error("MSSQL failed to run SP hss_delete_mme_identity with IMSI " + str(imsi))
            else:
                logging.debug("origin_host not present - not updating UE location in database")
        except:
            raise ValueError("MSSQL failed to update SQN for IMSI " + str(imsi))   
        

class MySQL:
    import mysql.connector
    def __init__(self):
        logging.info("Configured to use MySQL server: " + str(yaml_config['database']['mysql']['server']))
        self.server = yaml_config['database']['mysql']
        self.mydb = self.mysql.connector.connect(
          host=self.server['server'],
          user=self.server['username'],
          password=self.server['password'],
          database=self.server['database']
        )
        self.mydb.autocommit = True
        cursor = self.mydb.cursor(dictionary=True)
        self.cursor = cursor
        
    def GetSubscriberInfo(self, imsi):
        logging.debug("Getting subscriber info from MySQL for IMSI " + str(imsi))
        self.cursor.execute("select * from subscribers left join subscriber_apns on subscribers.imsi = subscriber_apns.imsi left join apns on subscriber_apns.apn_id = apns.apn_id where subscribers.imsi = " + str(imsi))
        subscriber_details = self.cursor.fetchall()
        return subscriber_details

    def UpdateSubscriber(self, imsi, sqn, rand, *args, **kwargs):
        logging.debug("Updating SQN for imsi " + str(imsi) + " to " + str(sqn))
        query = 'update subscribers set sqn = ' + str(sqn) + ' where imsi = ' + str(imsi)
        logging.debug(query)
        self.cursor.execute(query)
        
            
#Load DB functions based on Config
for db_option in yaml_config['database']:
    logging.debug("Selected DB backend " + str(db_option))
    break

if db_option == "mongodb":
    DB = MongoDB()
elif db_option == "mssql":
    DB = MSSQL()
elif db_option == "mysql":
    DB = MySQL()
else:
    logging.fatal("Failed to find any compatible database backends. Please ensure the database type you have in the config.yaml file corresponds to a database type defined in database.py Exiting.")
    sys.exit()

def GetSubscriberInfo(imsi):
    return DB.GetSubscriberInfo(imsi)

def UpdateSubscriber(imsi, sqn, rand):
    return DB.UpdateSubscriber(imsi, sqn, rand)

#Unit test if file called directly (instead of imported)
if __name__ == "__main__":
    DB.GetSubscriberInfo('204080902004931')
    DB.UpdateSubscriber('204080902004931', 998, '', origin_host='')
    DB.GetSubscriberLocation(imsi='204080902004931')