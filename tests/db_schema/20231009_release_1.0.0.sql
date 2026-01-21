BEGIN TRANSACTION;
CREATE TABLE apn (
	apn_id INTEGER NOT NULL,
	apn VARCHAR(50) NOT NULL,
	ip_version INTEGER,
	pgw_address VARCHAR(50),
	sgw_address VARCHAR(50),
	charging_characteristics VARCHAR(4),
	apn_ambr_dl INTEGER NOT NULL,
	apn_ambr_ul INTEGER NOT NULL,
	qci INTEGER,
	arp_priority INTEGER,
	arp_preemption_capability BOOLEAN,
	arp_preemption_vulnerability BOOLEAN,
	charging_rule_list VARCHAR(18),
	last_modified VARCHAR(100),
	PRIMARY KEY (apn_id)
);
CREATE TABLE auc (
	auc_id INTEGER NOT NULL,
	ki VARCHAR(32) NOT NULL,
	opc VARCHAR(32) NOT NULL,
	amf VARCHAR(4) NOT NULL,
	sqn BIGINT,
	iccid VARCHAR(20),
	imsi VARCHAR(18),
	batch_name VARCHAR(20),
	sim_vendor VARCHAR(20),
	esim BOOLEAN,
	lpa VARCHAR(128),
	pin1 VARCHAR(20),
	pin2 VARCHAR(20),
	puk1 VARCHAR(20),
	puk2 VARCHAR(20),
	kid VARCHAR(20),
	psk VARCHAR(128),
	des VARCHAR(128),
	adm1 VARCHAR(20),
	misc1 VARCHAR(128),
	misc2 VARCHAR(128),
	misc3 VARCHAR(128),
	misc4 VARCHAR(128),
	last_modified VARCHAR(100),
	PRIMARY KEY (auc_id),
	UNIQUE (iccid),
	UNIQUE (imsi)
);
CREATE TABLE charging_rule (
	charging_rule_id INTEGER NOT NULL,
	rule_name VARCHAR(20),
	qci INTEGER,
	arp_priority INTEGER,
	arp_preemption_capability BOOLEAN,
	arp_preemption_vulnerability BOOLEAN,
	mbr_dl INTEGER NOT NULL,
	mbr_ul INTEGER NOT NULL,
	gbr_dl INTEGER NOT NULL,
	gbr_ul INTEGER NOT NULL,
	tft_group_id INTEGER,
	precedence INTEGER,
	rating_group INTEGER,
	last_modified VARCHAR(100),
	PRIMARY KEY (charging_rule_id)
);
CREATE TABLE eir (
	eir_id INTEGER NOT NULL,
	imei VARCHAR(60),
	imsi VARCHAR(60),
	regex_mode INTEGER,
	match_response_code INTEGER,
	last_modified VARCHAR(100),
	PRIMARY KEY (eir_id)
);
CREATE TABLE eir_history (
	imsi_imei_history_id INTEGER NOT NULL,
	imsi_imei VARCHAR(60),
	match_response_code INTEGER,
	imsi_imei_timestamp DATETIME,
	last_modified VARCHAR(100),
	PRIMARY KEY (imsi_imei_history_id),
	UNIQUE (imsi_imei)
);
-- NOTE: sh_profile might be TEXT(12000) instead of TEXT depending on the
-- db_type. Use TEXT here, which works with all db_types.
-- https://github.com/nickvsnetworking/pyhss/commit/7d66298698d92176be1fef212de409a3ecfcdaf6
CREATE TABLE ims_subscriber (
	ims_subscriber_id INTEGER NOT NULL,
	msisdn VARCHAR(18),
	msisdn_list VARCHAR(1200),
	imsi VARCHAR(18),
	ifc_path VARCHAR(18),
	pcscf VARCHAR(512),
	pcscf_realm VARCHAR(512),
	pcscf_active_session VARCHAR(512),
	pcscf_timestamp DATETIME,
	pcscf_peer VARCHAR(512),
	sh_profile TEXT,
	scscf VARCHAR(512),
	scscf_timestamp DATETIME,
	scscf_realm VARCHAR(512),
	scscf_peer VARCHAR(512),
	last_modified VARCHAR(100),
	PRIMARY KEY (ims_subscriber_id),
	UNIQUE (msisdn)
);
CREATE TABLE subscriber (
	subscriber_id INTEGER NOT NULL,
	imsi VARCHAR(18),
	enabled BOOLEAN,
	auc_id INTEGER NOT NULL,
	default_apn INTEGER NOT NULL,
	apn_list VARCHAR(64) NOT NULL,
	msisdn VARCHAR(18),
	ue_ambr_dl INTEGER,
	ue_ambr_ul INTEGER,
	nam INTEGER,
	subscribed_rau_tau_timer INTEGER,
	serving_mme VARCHAR(512),
	serving_mme_timestamp DATETIME,
	serving_mme_realm VARCHAR(512),
	serving_mme_peer VARCHAR(512),
	last_modified VARCHAR(100),
	PRIMARY KEY (subscriber_id),
	UNIQUE (imsi),
	FOREIGN KEY(auc_id) REFERENCES auc (auc_id),
	FOREIGN KEY(default_apn) REFERENCES apn (apn_id)
);
CREATE TABLE serving_apn (
	serving_apn_id INTEGER NOT NULL,
	subscriber_id INTEGER,
	apn INTEGER,
	pcrf_session_id VARCHAR(100),
	subscriber_routing VARCHAR(100),
	ip_version INTEGER,
	serving_pgw VARCHAR(512),
	serving_pgw_timestamp DATETIME,
	serving_pgw_realm VARCHAR(512),
	serving_pgw_peer VARCHAR(512),
	last_modified VARCHAR(100),
	PRIMARY KEY (serving_apn_id),
	FOREIGN KEY(subscriber_id) REFERENCES subscriber (subscriber_id) ON DELETE CASCADE,
	FOREIGN KEY(apn) REFERENCES apn (apn_id) ON DELETE CASCADE
);
CREATE TABLE subscriber_attributes (
	subscriber_attributes_id INTEGER NOT NULL,
	subscriber_id INTEGER NOT NULL,
	"key" VARCHAR(60),
	last_modified VARCHAR(100),
	value VARCHAR(12000),
	PRIMARY KEY (subscriber_attributes_id),
	FOREIGN KEY(subscriber_id) REFERENCES subscriber (subscriber_id) ON DELETE CASCADE
);
CREATE TABLE subscriber_routing (
	subscriber_routing_id INTEGER NOT NULL,
	subscriber_id INTEGER,
	apn_id INTEGER,
	ip_version INTEGER,
	ip_address VARCHAR(254),
	last_modified VARCHAR(100),
	PRIMARY KEY (subscriber_routing_id),
	UNIQUE (subscriber_id, apn_id),
	FOREIGN KEY(subscriber_id) REFERENCES subscriber (subscriber_id) ON DELETE CASCADE,
	FOREIGN KEY(apn_id) REFERENCES apn (apn_id) ON DELETE CASCADE
);
CREATE TABLE tft (
	tft_id INTEGER NOT NULL,
	tft_group_id INTEGER NOT NULL,
	tft_string VARCHAR(100) NOT NULL,
	direction INTEGER NOT NULL,
	last_modified VARCHAR(100),
	PRIMARY KEY (tft_id)
);
CREATE TABLE operation_log (
	id INTEGER NOT NULL,
	item_id INTEGER NOT NULL,
	operation_id VARCHAR(36) NOT NULL,
	operation VARCHAR(10),
	changes TEXT,
	last_modified VARCHAR(100),
	timestamp DATETIME,
	table_name VARCHAR(255),
	apn_id INTEGER,
	subscriber_routing_id INTEGER,
	serving_apn_id INTEGER,
	auc_id INTEGER,
	subscriber_id INTEGER,
	ims_subscriber_id INTEGER,
	charging_rule_id INTEGER,
	tft_id INTEGER,
	eir_id INTEGER,
	imsi_imei_history_id INTEGER,
	subscriber_attributes_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(apn_id) REFERENCES apn (apn_id),
	FOREIGN KEY(subscriber_routing_id) REFERENCES subscriber_routing (subscriber_routing_id),
	FOREIGN KEY(serving_apn_id) REFERENCES serving_apn (serving_apn_id),
	FOREIGN KEY(auc_id) REFERENCES auc (auc_id),
	FOREIGN KEY(subscriber_id) REFERENCES subscriber (subscriber_id),
	FOREIGN KEY(ims_subscriber_id) REFERENCES ims_subscriber (ims_subscriber_id),
	FOREIGN KEY(charging_rule_id) REFERENCES charging_rule (charging_rule_id),
	FOREIGN KEY(tft_id) REFERENCES tft (tft_id),
	FOREIGN KEY(eir_id) REFERENCES eir (eir_id),
	FOREIGN KEY(imsi_imei_history_id) REFERENCES eir_history (imsi_imei_history_id),
	FOREIGN KEY(subscriber_attributes_id) REFERENCES subscriber_attributes (subscriber_attributes_id)
);
COMMIT;
