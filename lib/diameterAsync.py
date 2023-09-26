#Diameter Packet Decoder / Encoder & Tools
import math
import asyncio
from messagingAsync import RedisMessagingAsync


class DiameterAsync:

    def __init__(self, logTool):
        self.diameterCommandList = [
                {"commandCode": 257, "applicationId": 0, "flags": 80, "responseMethod": self.Answer_257, "failureResultCode": 5012 ,"requestAcronym": "CER", "responseAcronym": "CEA", "requestName": "Capabilites Exchange Request", "responseName": "Capabilites Exchange Answer"},
                {"commandCode": 280, "applicationId": 0, "flags": 80, "responseMethod": self.Answer_280, "failureResultCode": 5012 ,"requestAcronym": "DWR", "responseAcronym": "DWA", "requestName": "Device Watchdog Request", "responseName": "Device Watchdog Answer"},
                {"commandCode": 282, "applicationId": 0, "flags": 80, "responseMethod": self.Answer_282, "failureResultCode": 5012 ,"requestAcronym": "DPR", "responseAcronym": "DPA", "requestName": "Disconnect Peer Request", "responseName": "Disconnect Peer Answer"},
                {"commandCode": 300, "applicationId": 16777216, "responseMethod": self.Answer_16777216_300, "failureResultCode": 4100 ,"requestAcronym": "UAR", "responseAcronym": "UAA", "requestName": "User Authentication Request", "responseName": "User Authentication Answer"},
                {"commandCode": 301, "applicationId": 16777216, "responseMethod": self.Answer_16777216_301, "failureResultCode": 4100 ,"requestAcronym": "SAR", "responseAcronym": "SAA", "requestName": "Server Assignment Request", "responseName": "Server Assignment Answer"},
                {"commandCode": 302, "applicationId": 16777216, "responseMethod": self.Answer_16777216_302, "failureResultCode": 4100 ,"requestAcronym": "LIR", "responseAcronym": "LIA", "requestName": "Location Information Request", "responseName": "Location Information Answer"},
                {"commandCode": 303, "applicationId": 16777216, "responseMethod": self.Answer_16777216_303, "failureResultCode": 4100 ,"requestAcronym": "MAR", "responseAcronym": "MAA", "requestName": "Multimedia Authentication Request", "responseName": "Multimedia Authentication Answer"},
                {"commandCode": 306, "applicationId": 16777217, "responseMethod": self.Answer_16777217_306, "failureResultCode": 5001 ,"requestAcronym": "UDR", "responseAcronym": "UDA", "requestName": "User Data Request", "responseName": "User Data Answer"},
                {"commandCode": 307, "applicationId": 16777217, "responseMethod": self.Answer_16777217_307, "failureResultCode": 5001 ,"requestAcronym": "PRUR", "responseAcronym": "PRUA", "requestName": "Profile Update Request", "responseName": "Profile Update Answer"},
                {"commandCode": 265, "applicationId": 16777236, "responseMethod": self.Answer_16777236_265, "failureResultCode": 4100 ,"requestAcronym": "AAR", "responseAcronym": "AAA", "requestName": "AA Request", "responseName": "AA Answer"},
                {"commandCode": 258, "applicationId": 16777236, "responseMethod": self.Answer_16777236_258, "failureResultCode": 4100 ,"requestAcronym": "RAR", "responseAcronym": "RAA", "requestName": "Re Auth Request", "responseName": "Re Auth Answer"},
                {"commandCode": 275, "applicationId": 16777236, "responseMethod": self.Answer_16777236_275, "failureResultCode": 4100 ,"requestAcronym": "STR", "responseAcronym": "STA", "requestName": "Session Termination Request", "responseName": "Session Termination Answer"},
                {"commandCode": 274, "applicationId": 16777236, "responseMethod": self.Answer_16777236_274, "failureResultCode": 4100 ,"requestAcronym": "ASR", "responseAcronym": "ASA", "requestName": "Abort Session Request", "responseName": "Abort Session Answer"},
                {"commandCode": 272, "applicationId": 16777238, "responseMethod": self.Answer_16777238_272, "failureResultCode": 5012 ,"requestAcronym": "CCR", "responseAcronym": "CCA", "requestName": "Credit Control Request", "responseName": "Credit Control Answer"},
                {"commandCode": 318, "applicationId": 16777251, "flags": "c0", "responseMethod": self.Answer_16777251_318, "failureResultCode": 4100 ,"requestAcronym": "AIR", "responseAcronym": "AIA", "requestName": "Authentication Information Request", "responseName": "Authentication Information Answer"},
                {"commandCode": 316, "applicationId": 16777251, "responseMethod": self.Answer_16777251_316, "failureResultCode": 4100 ,"requestAcronym": "ULR", "responseAcronym": "ULA", "requestName": "Update Location Request", "responseName": "Update Location Answer"},
                {"commandCode": 321, "applicationId": 16777251, "responseMethod": self.Answer_16777251_321, "failureResultCode": 5012 ,"requestAcronym": "PUR", "responseAcronym": "PUA", "requestName": "Purge UE Request", "responseName": "Purge UE Answer"},
                {"commandCode": 323, "applicationId": 16777251, "responseMethod": self.Answer_16777251_323, "failureResultCode": 5012 ,"requestAcronym": "NOR", "responseAcronym": "NOA", "requestName": "Notify Request", "responseName": "Notify Answer"},
                {"commandCode": 324, "applicationId": 16777252, "responseMethod": self.Answer_16777252_324, "failureResultCode": 4100 ,"requestAcronym": "ECR", "responseAcronym": "ECA", "requestName": "ME Identity Check Request", "responseName": "ME Identity Check Answer"},
                {"commandCode": 8388622, "applicationId": 16777291, "responseMethod": self.Answer_16777291_8388622, "failureResultCode": 4100 ,"requestAcronym": "LRR", "responseAcronym": "LRA", "requestName": "LCS Routing Info Request", "responseName": "LCS Routing Info Answer"},
            ]

        self.redisMessaging = RedisMessagingAsync()
        self.logTool = logTool
        

    #Generates rounding for calculating padding
    async def myRound(self, n, base=4):
        if(n > 0):
            return math.ceil(n/4.0) * 4
        elif( n < 0):
            return math.floor(n/4.0) * 4
        else:
            return 4

    async def roundUpToMultiple(self, n, multiple):
        return ((n + multiple - 1) // multiple) * multiple

    async def getAvpData(self, avps, avp_code):
        #Loops through list of dicts generated by the packet decoder, and returns the data for a specific AVP code in list (May be more than one AVP with same code but different data)
        misc_data = []
        for keys in avps:
            if keys['avp_code'] == avp_code:
                misc_data.append(keys['misc_data'])
        return misc_data

    async def validateSingleAvp(self, data) -> bool:
        """
        Attempts to validate a single hex string diameter AVP as being an AVP.
        """
        try:
            avpCode = int(data[0:8], 16)
            # The next byte contains the AVP Flags
            avpFlags = data[8:10]
            # The next 3 bytes contain the AVP Length
            avpLength = int(data[10:16], 16)
            if avpFlags not in ['80', '40', '20', '00', 'c0']:
                #print(f"[AVP VALIDATION] Failed to validate due to invalid Flag: {data}")
                return False
            if int(len(data[16:]) / 2) < ((avpLength - 8)):
                #print(f"[AVP VALIDATION] Failed to validate due to invalid length: {data}")
                return False
            return True
        except Exception as e:
            return False


    async def decodeDiameterPacket(self, data):
        """
        Handles decoding of a full diameter packet.
        """
        packet_vars = {}
        avps = []

        if type(data) is bytes:
            data = data.hex()
        # One byte is 2 hex characters
        # First Byte is the Diameter Packet Version
        packet_vars['packet_version'] = data[0:2]
        # Next 3 Bytes are the length of the entire Diameter packet
        packet_vars['length'] = int(data[2:8], 16)
        # Next Byte is the Diameter Flags
        packet_vars['flags'] = data[8:10]
        packet_vars['flags_bin'] = bin(int(data[8:10], 16))[2:].zfill(8)
        # Next 3 Bytes are the Diameter Command Code
        packet_vars['command_code'] = int(data[10:16], 16)
        # Next 4 Bytes are the Application Id
        packet_vars['ApplicationId'] = int(data[16:24], 16)
        # Next 4 Bytes are the Hop By Hop Identifier
        packet_vars['hop-by-hop-identifier'] = data[24:32]
        # Next 4 Bytes are the End to End Identifier
        packet_vars['end-to-end-identifier'] = data[32:40]

        #We're enforcing correct length, and calculate the end byte based on the length of the remaining AVPs and the known 'length' packet var.

        lengthOfDiameterVars = int(len(data[:40]) / 2)
        #print(f"Length of Diameter Vars (Bytes): {lengthOfDiameterVars}")

        #Length of all AVPs, in bytes
        avpLength = int(packet_vars['length'] - lengthOfDiameterVars)
        #print(f"avpLength (bytes): {avpLength}")
        avpCharLength = int((avpLength * 2))
        #print(f"avpCharLength (chars): {avpCharLength}")
        #print(f"Total Data Length (bytes) {len(data) / 2}")
        remaining_avps = data[40:]

        #print(remaining_avps)

        avps = await self.decodeAvpPacket(remaining_avps)
        #print(f"Got Back: {avps}")

        return packet_vars, avps

    async def decodeAvpPacket(self, data):
        """
        Returns a list of decoded AVP Packet dictionaries.
        """
        processed_avps = []
        # Initialize a failsafe counter, to prevent packets that pass validation but aren't AVPs from causing an infinite loop
        failsafeCounter = 0

        # If the avp data is 8 bytes (16 chars) or less, it's invalid.
        if len(data) < 16:
            return []

        # Keep processing AVPs until they're all dealt with
        while len(data) > 16:
            try:
                failsafeCounter += 1

                if failsafeCounter > 100:
                    break
                avp_vars = {}
                #print(f"AVP Data: {data}")
                # The first 4 bytes contains the AVP code
                avp_vars['avp_code'] = int(data[0:8], 16)
                # The next byte contains the AVP Flags
                avp_vars['avp_flags'] = data[8:10]
                # The next 3 bytes contains the AVP Length
                avp_vars['avp_length'] = int(data[10:16], 16)
                #print(f"Individual AVP Length: {avp_vars['avp_length']}")
                # The remaining bytes (until the end, defined by avp_length) is the AVP payload.
                # Padding is excluded from avp_length. It's calculated separately, and unknown by the AVP itself.
                # We calculate the avp payload length (in bytes) by subtracting 8, because the avp headers are always 8 bytes long. 
                # The result is then multiplied by 2 to give us chars.
                avpPayloadLength = int((avp_vars['avp_length'])*2)
                #print(f"AVP Payload Length (Chars): {avpPayloadLength}")

                # Work out our vendor id and add the payload itself (misc_data)
                if avp_vars['avp_code'] == 266:
                    avp_vars['vendor_id'] = int(data[16:24], 16)
                    avp_vars['misc_data'] = data[16:avpPayloadLength]
                else:
                    avp_vars['vendor_id'] = ''
                    avp_vars['misc_data'] = data[16:avpPayloadLength]

                # Rounds up the length to the nearest multiple of 4, which we can differential against the avp length to give us the padding length (if required)
                avp_padded_length = int((await(self.roundUpToMultiple(avp_vars['avp_length'], 4))))
                # avp_padded_length = (avp_vars['avp_length'] + 3) // 4 * 4 
                avpPaddingLength = ((avp_padded_length - avp_vars['avp_length']) * 2)
                #print(f"AVP Padding length (Chars): {avpPaddingLength}")

                avp_vars['sub_avps'] = []

                # Check if the payload data contains sub or grouped AVPs inside
                payloadContainsSubAvps = await(self.validateSingleAvp(avp_vars['misc_data']))

                if payloadContainsSubAvps:
                    # If the payload contains sub or grouped AVPs, assign misc_data to sub_avps to start working through them
                    sub_avp_data = avp_vars['misc_data']

                while payloadContainsSubAvps:
                    failsafeCounter += 1

                    if failsafeCounter > 100:
                        break
                    sub_avp = {}
                    sub_avp['avp_code'] = int(sub_avp_data[0:8], 16)
                    sub_avp['avp_flags'] = sub_avp_data[8:10]
                    sub_avp['avp_length'] = int(sub_avp_data[10:16], 16)
                    sub_avpPayloadLength = int((sub_avp['avp_length'])*2)

                    if sub_avp['avp_code'] == 266:
                        sub_avp['vendor_id'] = int(sub_avp_data[16:24], 16)
                        sub_avp['misc_data'] = sub_avp_data[16:sub_avpPayloadLength]
                    else:
                        sub_avp['vendor_id'] = ''
                        sub_avp['misc_data'] = sub_avp_data[16:sub_avpPayloadLength]

                    avp_vars['sub_avps'].append(sub_avp)

                    #print(f"Sub Avp Data before trimming: {sub_avp_data}")
                    #print(f"Sub Avp payload length: {sub_avpPayloadLength}")
                    sub_avp_data = sub_avp_data[sub_avpPayloadLength:]
                    avp_vars['misc_data'] = avp_vars['misc_data'][sub_avpPayloadLength:]
                    #print(f"Sub Avp Data after trimming: {sub_avp_data}")
                    payloadContainsSubAvps = await(self.validateSingleAvp(sub_avp_data))
                
                if avpPaddingLength > 0:
                    processed_avps.append(avp_vars)
                    data = data[avpPayloadLength+avpPaddingLength:]
                else:
                    processed_avps.append(avp_vars)
                    data = data[avpPayloadLength:]
            except Exception as e:
                #print(f"EXCEPTION: {e}")
                continue

        return processed_avps

    async def getPeerType(self, originHost: str) -> str:
            try:
                peerTypes = ['mme', 'pgw', 'icscf', 'scscf', 'hss', 'ocs']

                for peer in peerTypes:
                    if peer in originHost.lower():
                        return peer
                
            except Exception as e:
                return ''

    async def getConnectedPeersByType(self, peerType: str) -> list:
            try:
                peerType = peerType.lower()
                peerTypes = ['mme', 'pgw', 'icscf', 'scscf', 'hss', 'ocs']

                if peerType not in peerTypes:
                    return []
                filteredConnectedPeers = []
                activePeers = await(self.redisMessaging.getValue(key="ActiveDiameterPeers"))

                for key, value in activePeers.items():
                    if activePeers.get(key, {}).get('peerType', '') == 'pgw' and activePeers.get(key, {}).get('connectionStatus', '') == 'connected':
                        filteredConnectedPeers.append(activePeers.get(key, {}))
                
                return filteredConnectedPeers

            except Exception as e:
                return []


    async def getDiameterMessageType(self, binaryData: str) -> dict:
        packet_vars, avps = await(self.decodeDiameterPacket(binaryData))
        response = {}
        
        for diameterApplication in self.diameterCommandList:
            try:
                assert(packet_vars["command_code"] == diameterApplication["commandCode"])
                assert(packet_vars["ApplicationId"] == diameterApplication["applicationId"])
                response['inbound'] = diameterApplication["requestAcronym"]
                response['outbound'] = diameterApplication["responseAcronym"]
            except Exception as e:
                continue
        
        return response

    async def generateDiameterResponse(self, binaryData: str) -> str:
        packet_vars, avps = await(self.decodeDiameterPacket(binaryData))
        response = ''

        # Drop packet if it's a response packet:
        if packet_vars["flags_bin"][0:1] == "0":
            return
        
        for diameterApplication in self.diameterCommandList:
            try:
                assert(packet_vars["command_code"] == diameterApplication["commandCode"])
                assert(packet_vars["ApplicationId"] == diameterApplication["applicationId"])
                if 'flags' in diameterApplication:
                    assert(str(packet_vars["flags"]) == str(diameterApplication["flags"]))
                response = diameterApplication["responseMethod"](packet_vars, avps)
            except Exception as e:
                continue
        
        return response
    
    async def Answer_257(self):
        pass

    async def Answer_16777238_272(self):
        pass

    async def Answer_280(self):
        pass

    async def Answer_282(self):
        pass

    async def Answer_16777251_318(self):
        pass
    
    async def Answer_16777251_316(self):
        pass

    async def Answer_16777251_321(self):
        pass

    async def Answer_16777251_323(self):
        pass

    async def Answer_16777216_300(self):
        pass

    async def Answer_16777216_301(self):
        pass

    async def Answer_16777216_302(self):
        pass

    async def Answer_16777216_303(self):
        pass

    async def Answer_16777217_306(self):
        pass

    async def Answer_16777217_307(self):
        pass

    async def Answer_16777252_324(self):
        pass

    async def Answer_16777291_8388622(self):
        pass

    async def Answer_16777236_265(self):
        pass

    async def Answer_16777236_258(self):
        pass

    async def Answer_16777236_275(self):
        pass

    async def Answer_16777236_274(self):
        pass