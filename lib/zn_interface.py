#!/usr/bin/env python3
"""
Zn-Interface Extension für PyHSS
Implementiert 3GPP TS 29.109 für GBA (Generic Bootstrapping Architecture)
Unterstützt Multimedia-Authentication-Request (MAR) und -Answer (MAA)
"""

import binascii
import hashlib
import base64
import os
from datetime import datetime, timedelta

class ZnInterface:
    """
    Zn-Interface Implementation für BSF-HSS Kommunikation
    """
    
    def __init__(self, diameter_instance, database_instance, config):
        self.diameter = diameter_instance
        self.database = database_instance
        self.config = config
        self.logTool = diameter_instance.logTool
        self.redisMessaging = diameter_instance.redisMessaging
        
        # GBA/Zn spezifische Konfiguration
        self.zn_enabled = config.get('hss', {}).get('Zn_enabled', False)
        self.bsf_config = config.get('hss', {}).get('bsf', {})
        self.gaa_key_lifetime = self.bsf_config.get('gaa_key_lifetime', 3600)
        
    def generate_btid(self, rand, bsf_hostname=None):
        """
        Generiert B-TID (Bootstrapping Transaction Identifier)
        Format: base64(RAND)@bsf_hostname
        
        Args:
            rand: 16 Byte RAND Wert
            bsf_hostname: BSF Hostname (optional)
            
        Returns:
            B-TID als String
        """
        if bsf_hostname is None:
            bsf_hostname = self.bsf_config.get('bsf_hostname', 'bsf.epc.mnc001.mcc001.3gppnetwork.org')
        
        # RAND in Base64 kodieren
        rand_b64 = base64.b64encode(rand).decode('ascii')
        btid = f"{rand_b64}@{bsf_hostname}"
        
        self.logTool.log(service='HSS', level='debug', 
                        message=f"Generated B-TID: {btid}", 
                        redisClient=self.redisMessaging)
        
        return btid
    
    def derive_ks_naf(self, ck, ik, naf_id, impi):
        """
        Leitet Ks_NAF gemäß 3GPP TS 33.220 ab
        Ks_NAF = KDF(CK || IK, "gba-me", RAND, IMPI, NAF_Id)
        
        Args:
            ck: Cipher Key (16 bytes)
            ik: Integrity Key (16 bytes)
            naf_id: NAF Identifier (FQDN des NAF)
            impi: IMS Private Identity
            
        Returns:
            Ks_NAF (32 bytes)
        """
        # Ks = CK || IK
        ks = ck + ik
        
        # NAF_Id kodieren
        naf_id_bytes = naf_id.encode('utf-8')
        impi_bytes = impi.encode('utf-8')
        
        # Key Derivation Function (vereinfacht - in Produktion HMAC-SHA256 verwenden)
        kdf_input = ks + b'gba-me' + naf_id_bytes + impi_bytes
        ks_naf = hashlib.sha256(kdf_input).digest()
        
        self.logTool.log(service='HSS', level='debug', 
                        message=f"Derived Ks_NAF for NAF: {naf_id}", 
                        redisClient=self.redisMessaging)
        
        return ks_naf
    
    def derive_ks_ext_naf(self, kc, naf_id, impi):
        """
        Leitet Ks_ext_NAF für 2G/3G Netzwerke ab
        Ks_ext_NAF = KDF(Kc, "gba-me", RAND, IMPI, NAF_Id)
        
        Args:
            kc: Cipher Key aus 2G/3G (8 bytes)
            naf_id: NAF Identifier
            impi: IMS Private Identity
            
        Returns:
            Ks_ext_NAF (32 bytes)
        """
        naf_id_bytes = naf_id.encode('utf-8')
        impi_bytes = impi.encode('utf-8')
        
        # Key Derivation für 2G/3G
        kdf_input = kc + b'gba-me' + naf_id_bytes + impi_bytes
        ks_ext_naf = hashlib.sha256(kdf_input).digest()
        
        self.logTool.log(service='HSS', level='debug', 
                        message=f"Derived Ks_ext_NAF for 2G/3G NAF: {naf_id}", 
                        redisClient=self.redisMessaging)
        
        return ks_ext_naf
    
    def validate_naf_authorization(self, naf_hostname):
        """
        Prüft ob ein NAF autorisiert ist, GBA zu verwenden
        
        Args:
            naf_hostname: Hostname des NAF
            
        Returns:
            Boolean - True wenn autorisiert
        """
        naf_groups = self.bsf_config.get('naf_groups', [])
        
        for group in naf_groups:
            if naf_hostname in group.get('naf_hostnames', []):
                self.logTool.log(service='HSS', level='debug', 
                                message=f"NAF {naf_hostname} is authorized", 
                                redisClient=self.redisMessaging)
                return True
        
        self.logTool.log(service='HSS', level='warning', 
                        message=f"NAF {naf_hostname} is NOT authorized", 
                        redisClient=self.redisMessaging)
        return False


class ZnDiameterExtension:
    """
    Diameter Protokoll Extension für Zn-Interface
    Fügt MAR/MAA Unterstützung hinzu
    """
    
    def __init__(self, diameter_instance):
        self.diameter = diameter_instance
        self.logTool = diameter_instance.logTool
        self.redisMessaging = diameter_instance.redisMessaging
        
    def register_zn_commands(self):
        """
        Registriert Zn-Interface spezifische Diameter Commands
        """
        # Application ID 16777220 = Zh/Zn Interface
        zn_commands = [
            {
                "commandCode": 303, 
                "applicationId": 16777220, 
                "responseMethod": self.Answer_16777220_303, 
                "failureResultCode": 5001,
                "requestAcronym": "MAR", 
                "responseAcronym": "MAA", 
                "requestName": "Multimedia Authentication Request", 
                "responseName": "Multimedia Authentication Answer"
            }
        ]
        
        # Füge Zn Commands zur Diameter Command List hinzu
        self.diameter.diameterCommandList.extend(zn_commands)
        
        self.logTool.log(service='HSS', level='info', 
                        message="Zn-Interface commands registered", 
                        redisClient=self.redisMessaging)
    
    def Answer_16777220_303(self, packet_vars, avps):
        """
        3GPP Zh/Zn Multimedia Authentication Answer (MAA)
        Implementiert 3GPP TS 29.109
        
        Args:
            packet_vars: Diameter Packet Variablen
            avps: Liste der AVPs aus dem Request
            
        Returns:
            Diameter MAA Response
        """
        avp = ''
        
        self.logTool.log(service='HSS', level='info', 
                        message="Processing Multimedia Authentication Request (MAR) for Zn-Interface", 
                        redisClient=self.redisMessaging)
        
        # Session-ID aus Request übernehmen
        try:
            session_id = self.diameter.get_avp_data(avps, 263)[0]
            avp += self.diameter.generate_avp(263, 40, session_id)
        except Exception as e:
            self.logTool.log(service='HSS', level='error', 
                            message=f"Failed to get Session-ID: {str(e)}", 
                            redisClient=self.redisMessaging)
            return self.diameter.Respond_ResultCode(packet_vars, avps, 5012)
        
        # Origin Host und Realm
        avp += self.diameter.generate_avp(264, 40, self.diameter.OriginHost)
        avp += self.diameter.generate_avp(296, 40, self.diameter.OriginRealm)
        
        # User-Name (IMPI) extrahieren
        try:
            username_avp = self.diameter.get_avp_data(avps, 1)[0]
            username = binascii.unhexlify(username_avp).decode('utf-8')
            self.logTool.log(service='HSS', level='debug', 
                            message=f"Processing MAR for user: {username}", 
                            redisClient=self.redisMessaging)
        except Exception as e:
            self.logTool.log(service='HSS', level='error', 
                            message=f"Failed to extract username: {str(e)}", 
                            redisClient=self.redisMessaging)
            return self.diameter.Respond_ResultCode(packet_vars, avps, 5001)
        
        # Public-Identity (IMPU) extrahieren
        try:
            public_identity_avp = self.diameter.get_avp_data(avps, 601)[0]
            public_identity = binascii.unhexlify(public_identity_avp).decode('utf-8')
            
            # IMSI aus Public Identity extrahieren
            if '@' in username:
                imsi = username.split('@')[0]
            else:
                imsi = username
                
            self.logTool.log(service='HSS', level='debug', 
                            message=f"Extracted IMSI: {imsi}", 
                            redisClient=self.redisMessaging)
        except Exception as e:
            self.logTool.log(service='HSS', level='error', 
                            message=f"Failed to extract public identity: {str(e)}", 
                            redisClient=self.redisMessaging)
            return self.diameter.Respond_ResultCode(packet_vars, avps, 5001)
        
        # Subscriber Details aus Datenbank holen
        try:
            subscriber_details = self.diameter.database.Get_Subscriber(imsi=imsi)
            if subscriber_details is None:
                self.logTool.log(service='HSS', level='warning', 
                                message=f"Subscriber not found: {imsi}", 
                                redisClient=self.redisMessaging)
                return self.diameter.Respond_ResultCode(packet_vars, avps, 5001)
        except Exception as e:
            self.logTool.log(service='HSS', level='error', 
                            message=f"Database error: {str(e)}", 
                            redisClient=self.redisMessaging)
            return self.diameter.Respond_ResultCode(packet_vars, avps, 5012)
        
        # Authentication Scheme auslesen (GBA_ME oder GBA_U)
        auth_scheme = "GBA_ME"  # Default
        try:
            # AVP 612 = SIP-Auth-Data-Item
            sip_auth_data = self.diameter.get_avp_data(avps, 612)[0]
            # AVP 608 = SIP-Authentication-Scheme in SIP-Auth-Data-Item
            for sub_avp in self.diameter.decode_avp(sip_auth_data):
                if sub_avp['avp_code'] == 608:
                    auth_scheme = binascii.unhexlify(sub_avp['misc_data']).decode('utf-8')
                    self.logTool.log(service='HSS', level='debug', 
                                    message=f"Auth scheme requested: {auth_scheme}", 
                                    redisClient=self.redisMessaging)
        except:
            pass
        
        # PLMN aus Subscriber Details
        plmn = self.diameter.generate_plmn(subscriber_details['msisdn'])
        
        # Authentication Vectors generieren für GBA
        try:
            from lib.S6a_crypt import generate_maa_vector
            
            # AuC Details holen
            auc_id = subscriber_details.get('auc_id')
            auc = self.diameter.database.Get_AuC(auc_id)
            
            if auc is None:
                self.logTool.log(service='HSS', level='error', 
                                message=f"No AuC data for subscriber: {imsi}", 
                                redisClient=self.redisMessaging)
                return self.diameter.Respond_ResultCode(packet_vars, avps, 4181)
            
            # SQN incrementieren
            sqn = int(auc['sqn'])
            sqn += 1
            self.diameter.database.Update_AuC(auc_id, sqn=sqn)
            
            # Generiere MAA Vector (RAND, AUTN, XRES, CK, IK)
            (rand, autn, xres, ck, ik) = generate_maa_vector(
                auc['ki'], 
                auc['opc'], 
                auc['amf'],
                sqn,
                plmn
            )
            
            self.logTool.log(service='HSS', level='debug', 
                            message="Successfully generated GBA authentication vector", 
                            redisClient=self.redisMessaging)
            
        except Exception as e:
            self.logTool.log(service='HSS', level='error', 
                            message=f"Failed to generate auth vector: {str(e)}", 
                            redisClient=self.redisMessaging)
            return self.diameter.Respond_ResultCode(packet_vars, avps, 4181)
        
        # Public Identity AVP hinzufügen
        avp += self.diameter.generate_vendor_avp(601, "c0", 10415, 
                                                str(binascii.hexlify(str.encode(public_identity)), 'ascii'))
        
        # Username AVP hinzufügen
        avp += self.diameter.generate_avp(1, 40, 
                                         str(binascii.hexlify(str.encode(username)), 'ascii'))
        
        # SIP-Auth-Data-Item konstruieren
        # AVP 613 = SIP-Item-Number
        avp_SIP_Item_Number = self.diameter.generate_vendor_avp(613, "c0", 10415, 
                                                                format(int(0), "x").zfill(8))
        
        # AVP 608 = SIP-Authentication-Scheme
        avp_SIP_Authentication_Scheme = self.diameter.generate_vendor_avp(608, "c0", 10415, 
                                                                          str(binascii.hexlify(auth_scheme.encode()), 'ascii'))
        
        # AVP 609 = SIP-Authenticate (RAND || AUTN)
        SIP_Authenticate = rand + autn
        avp_SIP_Authenticate = self.diameter.generate_vendor_avp(609, "c0", 10415, 
                                                                 str(binascii.hexlify(SIP_Authenticate), 'ascii'))
        
        # AVP 610 = SIP-Authorization (XRES)
        avp_SIP_Authorization = self.diameter.generate_vendor_avp(610, "c0", 10415, 
                                                                  str(binascii.hexlify(xres), 'ascii'))
        
        # AVP 625 = Confidentiality-Key (CK)
        avp_Confidentiality_Key = self.diameter.generate_vendor_avp(625, "c0", 10415, 
                                                                    str(binascii.hexlify(ck), 'ascii'))
        
        # AVP 626 = Integrity-Key (IK)
        avp_Integrity_Key = self.diameter.generate_vendor_avp(626, "c0", 10415, 
                                                              str(binascii.hexlify(ik), 'ascii'))
        
        # Kombiniere alle SIP-Auth-Data-Item Sub-AVPs
        auth_data_item = (avp_SIP_Item_Number + 
                         avp_SIP_Authentication_Scheme + 
                         avp_SIP_Authenticate + 
                         avp_SIP_Authorization + 
                         avp_Confidentiality_Key + 
                         avp_Integrity_Key)
        
        # AVP 612 = SIP-Auth-Data-Item
        avp += self.diameter.generate_vendor_avp(612, "c0", 10415, auth_data_item)
        
        # AVP 607 = SIP-Number-Auth-Items (Anzahl der Auth Items = 1)
        avp += self.diameter.generate_vendor_avp(607, "c0", 10415, "00000001")
        
        # AVP 268 = Result-Code (DIAMETER_SUCCESS = 2001)
        avp += self.diameter.generate_avp(268, 40, "000007d1")
        
        # Auth-Session-State (NO_STATE_MAINTAINED = 1)
        avp += self.diameter.generate_avp(277, 40, "00000001")
        
        # Vendor-Specific-Application-Id
        avp += self.diameter.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c010055d4")
        
        # B-TID für Logging speichern (optional)
        try:
            from lib.zn_interface import ZnInterface
            zn = ZnInterface(self.diameter, self.diameter.database, self.diameter.config)
            btid = zn.generate_btid(rand)
            
            self.logTool.log(service='HSS', level='info', 
                            message=f"Generated B-TID: {btid} for IMSI: {imsi}", 
                            redisClient=self.redisMessaging)
        except:
            pass
        
        # Metrics senden
        self.redisMessaging.sendMetric(
            serviceName='diameter',
            metricName='prom_diam_auth_event_count',
            metricType='counter',
            metricAction='inc',
            metricValue=1.0,
            metricLabels={
                "diameter_application_id": 16777220,
                "diameter_cmd_code": 303,
                "event": "Successful_GBA_Auth",
                "imsi_prefix": str(imsi[0:6])
            },
            metricHelp='Diameter GBA Authentication Counters',
            metricExpiry=60,
            usePrefix=True,
            prefixHostname=self.diameter.hostname,
            prefixServiceName='metric'
        )
        
        # Generiere Diameter MAA Response
        response = self.diameter.generate_diameter_packet(
            "01",  # Version
            "40",  # Flags (Response)
            303,   # Command Code (MAR/MAA)
            16777220,  # Application ID (Zh/Zn)
            packet_vars['hop-by-hop-identifier'],
            packet_vars['end-to-end-identifier'],
            avp
        )
        
        self.logTool.log(service='HSS', level='info', 
                        message=f"Successfully processed MAR for IMSI {imsi}, returning MAA", 
                        redisClient=self.redisMessaging)
        
        return response


# Integration in bestehendes Diameter System
def initialize_zn_interface(diameter_instance, config):
    """
    Initialisiert das Zn-Interface im bestehenden Diameter System
    
    Args:
        diameter_instance: Instanz der Diameter Klasse
        config: Konfiguration (aus config.yaml)
    """
    if not config.get('hss', {}).get('Zn_enabled', False):
        diameter_instance.logTool.log(
            service='HSS', 
            level='info', 
            message="Zn-Interface is disabled in configuration", 
            redisClient=diameter_instance.redisMessaging
        )
        return
    
    # Zn Diameter Extension initialisieren
    zn_extension = ZnDiameterExtension(diameter_instance)
    zn_extension.register_zn_commands()
    
    # ZnInterface Logik initialisieren
    zn_interface = ZnInterface(diameter_instance, diameter_instance.database, config)
    
    diameter_instance.logTool.log(
        service='HSS', 
        level='info', 
        message="Zn-Interface initialized successfully", 
        redisClient=diameter_instance.redisMessaging
    )
    
    return zn_extension, zn_interface
