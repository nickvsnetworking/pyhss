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
    import pymssql
    def __init__(self):
        logging.info("Configured to use MS-SQL server: " + str(yaml_config['database']['mssql']['server']))
        self.server = yaml_config['database']['mssql']
        try:
            conn = self.pymssql.connect(self.server['server'], self.server['username'], self.server['password'], self.server['database'], as_dict=True, autocommit=True)
            self.cursor = conn.cursor()
        except:
            #If failed to connect to server
            logging.fatal("Failed to connect to MSSQL server at " + str(self.server['server']))
            raise OSError("Failed to connect to MSSQL server at " + str(self.server['server']))
            sys.exit()



    def GetSubscriberInfo(self, imsi):
        logging.debug("Getting subscriber info from MSSQL for IMSI " + str(imsi))
        self.cursor.execute('SELECT * FROM imsi WHERE IMSI=%s', str(imsi))
        for row in self.cursor:
            subscriber_details = {}
            subscriber_details['K'] = row['Ki']
            subscriber_details['SQN'] = row['seqNB']
            logging.debug('Returned data from DB:')
            logging.debug(subscriber_details)
            return subscriber_details
        #If we've made it to here it's because we haven't returned a result.
        #if no results returned raise error
        raise ValueError("MSSQL has no matching subscriber details for IMSI " + str(imsi))            


    def UpdateSubscriber(self, imsi, sqn, rand):
        logging.debug("Updating SQN for imsi " + str(imsi) + " to " + str(sqn))
        self.cursor.execute('update imsi set seqNB = ' + str(sqn) + ' where IMSI = ' + str(imsi))
        

# class MySQL:
#     def __init__():


#Load DB functions based on Config
for db_option in yaml_config['database']:
    logging.debug("Selected DB backend " + str(db_option))
    break

if db_option == "mongodb":
    DB = MongoDB()


if db_option == "mssql":
    DB = MSSQL()

else:
    logging.fatal("Failed to find any compatible database backends. Please ensure the database type you have in the config.yaml file corresponds to a database type defined in database.py Exiting.")
    sys.exit()

def GetSubscriberInfo(imsi):
    return DB.GetSubscriberInfo(imsi)

def UpdateSubscriber(imsi, sqn, rand):
    return DB.UpdateSubscriber(imsi, sqn, rand)

#Unit test if file called directly (instead of imported)
if __name__ == "__main__":
    DB.GetSubscriberInfo('001010000000003')
    DB.UpdateSubscriber('001010000000003', 998, '')
