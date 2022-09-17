# PyHSS - Database Notes
PyHSS supports pretty much any database backend you like.

This means if you have an existing databsae storing all your subscriber data, you don't need to add another database, you can just add the queries you need to get this data and the credentials to access your database, into PyHSS and avoid reinventing the wheel.

All the magic happens in ```database.py``` which (Hopefully) is clear and easy to understand,

Each database backend has a class, containing a ```GetSubscriberInfo()``` function returns a dictionary.
Inside the function you'll need to query your database of choice and return a dict with the below keys:
```
subscriber_details = {'K': '465B5CE8B199B49FAA5F0A2EE238A6BC', 'OPc': 'E8ED289DEBA952E4283B54E88E6183CA', 'AMF': '8000', 'RAND': '', 'SQN': 22, 'APN_list': 'internet', 'pdn': [{'apn': 'internet'), 'pcc_rule': [], 'qos': {'qci': 9, 'arp': {'priority_level': 8, 'pre_emption_vulnerability': 1, 'pre_emption_capability': 1}}, 'type': 2}]}
```

For MongoDB we're storing the data already as a dictionary, but for SQL database like MSSQL or MySQL, you can run SELECT / EXEC queries and then map the fields returned into the dictionary as required. Taking a look at MSSQL section should give you an idea of how this is done.

The MongoDB schema is fully compatible with the Open5GS WebUI to make life easy, if you install the Open5GS-WebUI, you can use that to create subscribers.

MySQL support has had most of the groundwork done but has not yet been finished - To get it working you would need to map the names of the keys in the returned dict to match that of MongoDB.

A database option called "stub" can be used when no Database functionality is needed, to allow the library to start up without a database connected.

## PostgreSQL

Database Schema:
```
-- public.subscribers definition

-- Drop table

-- DROP TABLE public.subscribers;

CREATE TABLE public.subscribers (
	id int4 NOT NULL,
	imsi varchar NOT NULL, -- IMSI of Subscriber
	enabled bool NOT NULL DEFAULT true, -- Subscriber Enabled
	msisdn varchar NOT NULL, -- MISDN of the Subscriber
	ue_ambr_ul int4 NOT NULL DEFAULT 30000, -- UE level AMBR value (Uplink)
	ue_ambr_dl int4 NOT NULL DEFAULT 30000, -- UE level AMBR value (Downlink)
	network_access_mode int4 NOT NULL DEFAULT 0, -- Network Access Mode (0 is PACKET_AND_CIRCUIT)
	apn_default int4 NOT NULL, -- Default APN referenced by ID from the APN Table
	apn_additional_list varchar NULL, -- Additional APN referenced by ID from APN Table
	subscribed_rau_tau_timer int4 NULL DEFAULT 300, -- Periodic TAU Timer
	serving_pgw varchar NULL, -- Most recent serving PGW
	serving_pgw_timestamp timestamp NULL, -- Timestamp for serving_pgw entry
	serving_mme varchar NULL, -- Most recent serving MME
	serving_mme_timestamp timestamp NULL, -- Timestamp for serving_pgw entry
	CONSTRAINT subscribers_pkey PRIMARY KEY (id)
);
COMMENT ON TABLE public.subscribers IS 'Cellular Subscribers';

-- Column comments

COMMENT ON COLUMN public.subscribers.imsi IS 'IMSI of Subscriber';
COMMENT ON COLUMN public.subscribers.enabled IS 'Subscriber Enabled';
COMMENT ON COLUMN public.subscribers.msisdn IS 'MISDN of the Subscriber';
COMMENT ON COLUMN public.subscribers.ue_ambr_ul IS 'UE level AMBR value (Uplink)';
COMMENT ON COLUMN public.subscribers.ue_ambr_dl IS 'UE level AMBR value (Downlink)';
COMMENT ON COLUMN public.subscribers.network_access_mode IS 'Network Access Mode (0 is PACKET_AND_CIRCUIT)';
COMMENT ON COLUMN public.subscribers.apn_default IS 'Default APN referenced by ID from the APN Table';
COMMENT ON COLUMN public.subscribers.apn_additional_list IS 'Additional APN referenced by ID from APN Table';
COMMENT ON COLUMN public.subscribers.subscribed_rau_tau_timer IS 'Periodic TAU Timer';
COMMENT ON COLUMN public.subscribers.serving_pgw IS 'Most recent serving PGW';
COMMENT ON COLUMN public.subscribers.serving_pgw_timestamp IS 'Timestamp for serving_pgw entry';
COMMENT ON COLUMN public.subscribers.serving_mme IS 'Most recent serving MME';
COMMENT ON COLUMN public.subscribers.serving_mme_timestamp IS 'Timestamp for serving_pgw entry';


-- public.auc definition

-- Drop table

-- DROP TABLE public.auc;

CREATE TABLE public.auc (
	id int4 NOT NULL,
	imsi varchar NOT NULL, -- IMSI of the SIM
	ki varchar NOT NULL, -- Ki Key of the SIM
	opc varchar NOT NULL, -- OPc Key of the SIM
	sqn int4 NOT NULL DEFAULT 1, -- Sequence Number
	rand varchar NULL,
	amf varchar NOT NULL DEFAULT 8000, -- Authentication Management Field (Default 8000)
	CONSTRAINT auc_pkey PRIMARY KEY (id)
);
COMMENT ON TABLE public.auc IS 'Authentication information for SIMs';

-- Column comments

COMMENT ON COLUMN public.auc.imsi IS 'IMSI of the SIM';
COMMENT ON COLUMN public.auc.ki IS 'Ki Key of the SIM';
COMMENT ON COLUMN public.auc.opc IS 'OPc Key of the SIM';
COMMENT ON COLUMN public.auc.sqn IS 'Sequence Number';
COMMENT ON COLUMN public.auc.amf IS 'Authentication Management Field (Default 8000)';


-- public.apn definition

-- Drop table

-- DROP TABLE public.apn;

CREATE TABLE public.apn (
	id int4 NOT NULL,
	apn varchar NOT NULL, -- Access Point Name
	"pgw-address" varchar NULL, -- P-GW IP Address
	"sgw-address" varchar NULL, -- S-GW IP Address
	charging_characteristics varchar NULL, -- Hex representation of charging characteristics
	apn_ambr_dl int4 NULL, -- APN level AMBR (Downlink)
	apn_ambr_ul int4 NULL, -- APN level AMBR (Uplink)
	qci int4 NOT NULL DEFAULT 9, -- QoS Class Identifier
	arp_priority int4 NOT NULL DEFAULT 1, -- Alocation and Retention Policy Priority
	arp_preemption_capability bool NULL DEFAULT false,
	arp_preemption_vulnerability bool NULL DEFAULT true,
	CONSTRAINT apn_pkey PRIMARY KEY (id)
);

-- Column comments

COMMENT ON COLUMN public.apn.apn IS 'Access Point Name';
COMMENT ON COLUMN public.apn."pgw-address" IS 'P-GW IP Address';
COMMENT ON COLUMN public.apn."sgw-address" IS 'S-GW IP Address';
COMMENT ON COLUMN public.apn.charging_characteristics IS 'Hex representation of charging characteristics';
COMMENT ON COLUMN public.apn.apn_ambr_dl IS 'APN level AMBR (Downlink)';
COMMENT ON COLUMN public.apn.apn_ambr_ul IS 'APN level AMBR (Uplink)';
COMMENT ON COLUMN public.apn.qci IS 'QoS Class Identifier';
COMMENT ON COLUMN public.apn.arp_priority IS 'Alocation and Retention Policy Priority';

```

## MS-SQL
Running MSSQL inside container:
```docker run -e 'ACCEPT_EULA=Y' -e 'SA_PASSWORD=thisisthepasswordforMSSQL99#!' -p 1433:1433 -d mcr.microsoft.com/mssql/server:2017-latest```



## MySQL
Example Schema: 
```
CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON * . * TO 'newuser'@'localhost';
FLUSH PRIVILEGES;
-- Cell_HSS.apn definition

CREATE TABLE `apn` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `apn` varchar(100) NOT NULL COMMENT 'Access Point Name',
  `pgw-address` varchar(100) DEFAULT NULL COMMENT 'P-GW IP Address',
  `sgw-address` varchar(100) DEFAULT NULL COMMENT 'S-GW IP Address',
  `charging_characteristics` varchar(100) DEFAULT NULL COMMENT 'Hex representation of charging characteristics',
  `apn_ambr_dl` int(11) NOT NULL,
  `apn_ambr_ul` int(11) NOT NULL,
  `qci` int(11) NOT NULL,
  `arp_priority` int(11) NOT NULL,
  `arp_preemption_capability` bit(1) DEFAULT b'0',
  `arp_preemption_vulnerability` bit(1) DEFAULT b'1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4;


-- Cell_HSS.auc definition

CREATE TABLE `auc` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `imsi` varchar(100) NOT NULL COMMENT 'IMSI of SIM Card',
  `ki` varchar(100) NOT NULL COMMENT 'Ki Key of the SIM',
  `opc` varchar(100) NOT NULL COMMENT 'OPc Key of the SIM',
  `sqn` int(11) NOT NULL DEFAULT '1' COMMENT 'Sequence Number',
  `rand` varchar(100) DEFAULT NULL,
  `amf` varchar(100) NOT NULL DEFAULT '8000' COMMENT 'Authentication Management Field (Default 8000)',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;


-- Cell_HSS.subscribers definition

CREATE TABLE `subscribers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `imsi` varchar(100) NOT NULL COMMENT 'IMSI of Subscriber',
  `enabled` bit(1) DEFAULT b'1' COMMENT 'Subscriber Enabled',
  `msisdn` varchar(100) NOT NULL COMMENT 'MISDN of the Subscriber',
  `ue_ambr_ul` int(11) NOT NULL DEFAULT '30000' COMMENT 'UE level AMBR value (Uplink)',
  `ue_ambr_dl` int(11) NOT NULL DEFAULT '60000' COMMENT 'UE level AMBR value (Downlink)',
  `network_access_mode` int(11) NOT NULL DEFAULT '0' COMMENT 'Network Access Mode (0 is PACKET_AND_CIRCUIT)',
  `apn_default` int(11) NOT NULL COMMENT 'Default APN referenced by ID from the APN Table',
  `apn_additional_list` varchar(100) NOT NULL COMMENT 'Additional APN referenced by ID from APN Table',
  `subscribed_rau_tau_timer` int(11) NOT NULL DEFAULT '3000' COMMENT 'Periodic TAU Timer',
  `serving_pgw` varchar(100) DEFAULT NULL COMMENT 'Most recent serving PGW',
  `serving_pgw_timestamp` datetime DEFAULT NULL COMMENT 'Timestamp for serving_pgw entry',
  `serving_mme` varchar(100) DEFAULT NULL COMMENT 'Most recent serving MME',
  `serving_mme_timestamp` datetime DEFAULT NULL COMMENT 'Timestamp for serving_mme entry',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

```