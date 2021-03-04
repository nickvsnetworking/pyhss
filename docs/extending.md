# Extending
The Python Diameter library is contained within the file ``diameter.py``,

Inside is a class you instantiate with some basic variables such as the Origin Host, Origin Realm, Product Name and PLMN.

Under the class are a group of common functions for doing things like creating an AVP, or decoding an AVP. These should all be pretty self explanitory.

Then further down in the file are all the Request / Answer functions, for example, 'Answer_16777216_304' takes the packet_vars (a dict of the variables from the Diameter header) and avps (a list of AVPs and their values).

Then inside the response AVPs are constucted, some of which, like the Session-ID are based on the recieved session-ID, while others are generated based on the logic of what you're trying to do.

```
    #3GPP Example Answer
    def Answer_16777216_304(self, packet_vars, avps):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to recieved session ID
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        avp += self.generate_avp(268, 40, "000007d1")                                                   #Result Code - DIAMETER_SUCCESS
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth Session State        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                             #Origin Realm
                #* [ Proxy-Info ]
        proxy_host_avp = self.generate_avp(280, "40", str(binascii.hexlify(b'localdomain'),'ascii'))
        proxy_state_avp = self.generate_avp(33, "40", "0001")
        avp += self.generate_avp(284, "40", proxy_host_avp + proxy_state_avp)                 #Proxy-Info  AVP ( 284 )

        #* [ Route-Record ]
        avp += self.generate_avp(282, "40", str(binascii.hexlify(b'localdomain'),'ascii'))
        
        response = self.generate_diameter_packet("01", "40", 304, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response
```

To implement a new response is simply a matter of adding the *packet_vars['command_code']* and *packet_vars['ApplicationId']* to the if/elif loop in *hss.py*.

You can then access each of it's AVPs from the *avp* array, and the packet variables from the dictionary called *packet_vars*.
To add a new response you'd edit *diameter.py* and add a new function called Answer_YOURCOMMANDCODE, and build the AVPs and packet variables as required.
