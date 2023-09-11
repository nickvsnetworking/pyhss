#Diameter Packet Decoder / Encoder & Tools
import math
import asyncio
from messagingAsync import RedisMessagingAsync


class DiameterAsync:

    def __init__(self, logTool):
        self.diameterCommandList = [
                {"commandCode": 257, "applicationId": 0, "flags": 80, "responseMethod": self.Answer_257, "failureResultCode": 5012 ,"requestAcronym": "CER", "responseAcronym": "CEA", "requestName": "Capabilites Exchange Request", "responseName": "Capabilites Exchange Answer"},
                {"commandCode": 272, "applicationId": 16777238, "responseMethod": self.Answer_16777238_272, "failureResultCode": 5012 ,"requestAcronym": "CCR", "responseAcronym": "CCR", "requestName": "Credit Control Request", "responseName": "Credit Control Answer"},
                {"commandCode": 280, "applicationId": 0, "flags": 80, "responseMethod": self.Answer_280, "failureResultCode": 5012 ,"requestAcronym": "DWR", "responseAcronym": "DWA", "requestName": "Device Watchdog Request", "responseName": "Device Watchdog Answer"},
                {"commandCode": 282, "applicationId": 0, "flags": 80, "responseMethod": self.Answer_282, "failureResultCode": 5012 ,"requestAcronym": "DPR", "responseAcronym": "DPA", "requestName": "Disconnect Peer Request", "responseName": "Disconnect Peer Answer"},
                {"commandCode": 318, "applicationId": 16777251, "flags": "c0", "responseMethod": self.Answer_16777251_318, "failureResultCode": 4100 ,"requestAcronym": "AIR", "responseAcronym": "AIA", "requestName": "Authentication Information Request", "responseName": "Authentication Information Answer"},
                {"commandCode": 316, "applicationId": 16777251, "responseMethod": self.Answer_16777251_316, "failureResultCode": 4100 ,"requestAcronym": "ULR", "responseAcronym": "ULA", "requestName": "Update Location Request", "responseName": "Update Location Answer"},
                {"commandCode": 321, "applicationId": 16777251, "responseMethod": self.Answer_16777251_321, "failureResultCode": 5012 ,"requestAcronym": "PUR", "responseAcronym": "PUA", "requestName": "Purge UE Request", "responseName": "Purge UE Answer"},
                {"commandCode": 323, "applicationId": 16777251, "responseMethod": self.Answer_16777251_323, "failureResultCode": 5012 ,"requestAcronym": "NOR", "responseAcronym": "NOA", "requestName": "Notify Request", "responseName": "Notify Answer"},
                {"commandCode": 300, "applicationId": 16777216, "responseMethod": self.Answer_16777216_300, "failureResultCode": 4100 ,"requestAcronym": "UAR", "responseAcronym": "UAA", "requestName": "User Authentication Request", "responseName": "User Authentication Answer"},
                {"commandCode": 301, "applicationId": 16777216, "responseMethod": self.Answer_16777216_301, "failureResultCode": 4100 ,"requestAcronym": "SAR", "responseAcronym": "SAA", "requestName": "Server Assignment Request", "responseName": "Server Assignment Answer"},
                {"commandCode": 302, "applicationId": 16777216, "responseMethod": self.Answer_16777216_302, "failureResultCode": 4100 ,"requestAcronym": "LIR", "responseAcronym": "LIA", "requestName": "Location Information Request", "responseName": "Location Information Answer"},
                {"commandCode": 303, "applicationId": 16777216, "responseMethod": self.Answer_16777216_303, "failureResultCode": 4100 ,"requestAcronym": "MAR", "responseAcronym": "MAA", "requestName": "Multimedia Authentication Request", "responseName": "Multimedia Authentication Answer"},
                {"commandCode": 306, "applicationId": 16777217, "responseMethod": self.Answer_16777217_306, "failureResultCode": 5001 ,"requestAcronym": "UDR", "responseAcronym": "UDA", "requestName": "User Data Request", "responseName": "User Data Answer"},
                {"commandCode": 307, "applicationId": 16777217, "responseMethod": self.Answer_16777217_307, "failureResultCode": 5001 ,"requestAcronym": "PRUR", "responseAcronym": "PRUA", "requestName": "Profile Update Request", "responseName": "Profile Update Answer"},
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

    async def getAvpData(self, avps, avp_code):
        #Loops through list of dicts generated by the packet decoder, and returns the data for a specific AVP code in list (May be more than one AVP with same code but different data)
        misc_data = []
        for keys in avps:
            if keys['avp_code'] == avp_code:
                misc_data.append(keys['misc_data'])
        return misc_data

    # async def decodeDiameterPacket(self, data):
    #     packet_vars = {}
    #     avps = []
        
    #     if type(data) is bytes:
    #         data = data.hex()

    #     packet_vars['packet_version'] = data[0:2]
    #     packet_vars['length'] = int(data[2:8], 16)
    #     packet_vars['flags'] = data[8:10]
    #     packet_vars['flags_bin'] = bin(int(data[8:10], 16))[2:].zfill(8)
    #     packet_vars['command_code'] = int(data[10:16], 16)
    #     packet_vars['ApplicationId'] = int(data[16:24], 16)
    #     packet_vars['hop-by-hop-identifier'] = data[24:32]
    #     packet_vars['end-to-end-identifier'] = data[32:40]

    #     avp_sum = data[40:]

    #     avp_vars, remaining_avps = await(self.decodeAvpPacket(avp_sum))
    #     avps.append(avp_vars)
        
    #     while len(remaining_avps) > 0:
    #         avp_vars, remaining_avps = await(self.decodeAvpPacket(remaining_avps))
    #         avps.append(avp_vars)
    #     else:
    #         pass
    #     return packet_vars, avps

    async def decodeDiameterPacket(self, data):
        packet_vars = {}
        avps = []

        if type(data) is bytes:
            data = data.hex()

        packet_vars['packet_version'] = data[0:2]
        packet_vars['length'] = int(data[2:8], 16)
        packet_vars['flags'] = data[8:10]
        packet_vars['flags_bin'] = bin(int(data[8:10], 16))[2:].zfill(8)
        packet_vars['command_code'] = int(data[10:16], 16)
        packet_vars['ApplicationId'] = int(data[16:24], 16)
        packet_vars['hop-by-hop-identifier'] = data[24:32]
        packet_vars['end-to-end-identifier'] = data[32:40]

        remaining_avps = data[40:]

        while len(remaining_avps) > 0:
            avp_vars, remaining_avps = await self.decodeAvpPacket(remaining_avps)
            avps.append(avp_vars)
        else:
            pass

        return packet_vars, avps

    async def decodeAvpPacket(self, data):  
        avp_vars = {}
        sub_avps = []

        if len(data) <= 8:
            raise ValueError("Length of data is too short to be valid AVP")

        avp_vars['avp_code'] = int(data[0:8], 16)
            
        avp_vars['avp_flags'] = data[8:10]
        avp_vars['avp_length'] = int(data[10:16], 16)
        avp_padded_length = (avp_vars['avp_length'] + 3) // 4 * 4 

        if avp_vars['avp_flags'] == "c0":
            avp_vars['vendor_id'] = int(data[16:24], 16)
            avp_vars['misc_data'] = data[24:(avp_vars['avp_length']*2)]
        else:
            avp_vars['misc_data'] = data[16:(avp_vars['avp_length']*2)]

        sub_avp_data = avp_vars['misc_data']

        while len(sub_avp_data) >= 16:
            sub_avp_vars = {}
            sub_avp_vars['avp_code'] = int(sub_avp_data[0:8], 16)
            sub_avp_vars['avp_flags'] = sub_avp_data[8:10]
            sub_avp_vars['avp_length'] = int(sub_avp_data[10:16], 16)
            sub_avp_padded_length = (sub_avp_vars['avp_length'] + 3) // 4 * 4 

            if sub_avp_vars['avp_code'] > 9999:
                break

            if '40' <= sub_avp_vars['avp_flags'] <= '7F':  
                sub_avp_vars['vendor_id'] = int(sub_avp_data[16:24], 16)
                sub_avp_vars['misc_data'] = sub_avp_data[24:(24 + (sub_avp_vars['avp_length'] - 8) * 2)]
            else:
                sub_avp_vars['misc_data'] = sub_avp_data[16:(16 + (sub_avp_vars['avp_length'] - 8) * 2)]

            sub_avps.append(sub_avp_vars)

            sub_avp_data = sub_avp_data[(sub_avp_padded_length * 2):]

        avp_vars['sub_avps'] = sub_avps 

        if avp_vars['avp_length'] % 4  == 0:
            avp_vars['padding'] = 0
        else:
            rounded_value = await self.myRound(avp_vars['avp_length'])
            avp_vars['padding'] = int( rounded_value - avp_vars['avp_length']) * 2
        avp_vars['padded_data'] = data[(avp_vars['avp_length']*2):(avp_vars['avp_length']*2)+avp_vars['padding']]

        remaining_avps = data[(avp_padded_length * 2):]  

        return avp_vars, remaining_avps





    # async def decodeAvpPacket(self, data):  

    #     if len(data) <= 8:
    #         #if length is less than 8 it is too short to be an AVP and is most likely the data from the last AVP being attempted to be parsed as another AVP
    #         raise ValueError("Length of data is too short to be valid AVP")

    #     avp_vars = {}
    #     avp_vars['avp_code'] = int(data[0:8], 16)
        
    #     avp_vars['avp_flags'] = data[8:10]
    #     avp_vars['avp_length'] = int(data[10:16], 16)
    #     if avp_vars['avp_flags'] == "c0":
    #         #If c0 is present AVP is Vendor AVP
    #         avp_vars['vendor_id'] = int(data[16:24], 16)
    #         avp_vars['misc_data'] = data[24:(avp_vars['avp_length']*2)]
    #     else:
    #         #if is not a vendor AVP
    #         avp_vars['misc_data'] = data[16:(avp_vars['avp_length']*2)]

    #     if avp_vars['avp_length'] % 4  == 0:
    #         #Multiple of 4 - No Padding needed
    #         avp_vars['padding'] = 0
    #     else:
    #         #Not multiple of 4 - Padding needed
    #         rounded_value = await(self.myRound(avp_vars['avp_length']))
    #         avp_vars['padding'] = int( rounded_value - avp_vars['avp_length']) * 2
    #     avp_vars['padded_data'] = data[(avp_vars['avp_length']*2):(avp_vars['avp_length']*2)+avp_vars['padding']]


    #     #If body of avp_vars['misc_data'] contains AVPs, then decode each of them as a list of dicts like avp_vars['misc_data'] = [avp_vars, avp_vars]
    #     try:
    #         sub_avp_vars, sub_remaining_avps = await(self.decodeAvpPacket(avp_vars['misc_data']))
    #         #Sanity check - If the avp code is greater than 9999 it's probably not an AVP after all...
    #         if int(sub_avp_vars['avp_code']) > 9999:
    #             pass
    #         else:
    #             #If the decoded AVP is valid store it
    #             avp_vars['misc_data'] = []
    #             avp_vars['misc_data'].append(sub_avp_vars)
    #             #While there are more AVPs to be decoded, decode them:
    #             while len(sub_remaining_avps) > 0:
    #                 sub_avp_vars, sub_remaining_avps = await(self.decodeAvpPacket(sub_remaining_avps))
    #                 avp_vars['misc_data'].append(sub_avp_vars)
              
    #     except Exception as e:
    #         if str(e) == "invalid literal for int() with base 16: ''":
    #             pass
    #         elif str(e) == "Length of data is too short to be valid AVP":
    #             pass
    #         else:
    #             pass

        remaining_avps = data[(avp_vars['avp_length']*2)+avp_vars['padding']:]  #returns remaining data in avp string back for processing again
        return avp_vars, remaining_avps

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