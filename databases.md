# PyHSS - Database Notes
PyHSS supports pretty much any database backend you like.

All the magic happens in ```database.py``` which (Hopefully) is clear and easy to understand,

Each database backend has a class, containing a ```GetSubscriberInfo()``` function returns a dictionary.
Inside the function you'll need to query your database of choice and return a dict with the below keys:
```
subscriber_details = {'K': '465B5CE8B199B49FAA5F0A2EE238A6BC', 'OPc': 'E8ED289DEBA952E4283B54E88E6183CA', 'AMF': '8000', 'RAND': '', 'SQN': 22, 'APN_list': 'internet', 'pdn': [{'apn': 'internet'), 'pcc_rule': [], 'qos': {'qci': 9, 'arp': {'priority_level': 8, 'pre_emption_vulnerability': 1, 'pre_emption_capability': 1}}, 'type': 2}]}
```

PyHSS was developed for MongoDB initially and MS-SQL support has since been added and fully tested.
 
The MongoDB schema is fully compatible with the Open5GS WebUI to make life easy, if you install that and set the binding, you'll be set.

MySQL support has had most of the groundwork done but has not yet been finished - To get it working you would need to map the names of the keys in the returned dict to match that of MongoDB.

##MS-SQL
Running MSSQL inside container:
```docker run -e 'ACCEPT_EULA=Y' -e 'SA_PASSWORD=thisisthepasswordforMSSQL99#!' -p 1433:1433 -d mcr.microsoft.com/mssql/server:2017-latest```


## MySQL
Example Schema: 
```CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON * . * TO 'newuser'@'localhost';
FLUSH PRIVILEGES;

create table subscribers(
   id INT NOT NULL AUTO_INCREMENT,
   imsi VARCHAR(15) NOT NULL,
   opc VARCHAR(32) NOT NULL,
   k VARCHAR(32) NOT NULL,
   amf VARCHAR(4) NOT NULL,
   sqn VARCHAR(4) NOT NULL,
   ue_ambr_dl VARCHAR(32) NOT NULL,
   ue_ambr_ul VARCHAR(32) NOT NULL,
   submission_date DATE,
   PRIMARY KEY ( id )
);
insert into subscribers values( 1, '001010000000003', 'E8ED289DEBA952E4283B54E88E6183CA', 'E8ED289DEBA952E4283B54E88E6183CA', '8000', '0', '1024000', '1024000', '');
create table subscriber_apns(
   id INT NOT NULL AUTO_INCREMENT,
   imsi VARCHAR(15) NOT NULL,
   apn_id VARCHAR(32) NOT NULL,
   PRIMARY KEY ( id )
);
insert into subscriber_apns values('1', '001010000000003', '1');
create table apns(
   apn_id INT NOT NULL AUTO_INCREMENT,
   apn VARCHAR(32) NOT NULL,
   qci VARCHAR(32) NOT NULL,
   arp VARCHAR(32) NOT NULL,
   preemption_capability VARCHAR(32) NOT NULL,
   preemption_vunerability VARCHAR(32) NOT NULL,
   apn_ambr_dl VARCHAR(32) NOT NULL,
   apn_ambr_ul VARCHAR(32) NOT NULL,
   PRIMARY KEY ( apn_id )
);
insert into apns values ('1', 'internet', '9', '8', 'Disabled', 'Disabled', '1024000', '1024000');
```