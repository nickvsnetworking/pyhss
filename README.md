# PyHSS

Python Home Subscriber Server implementing basic Diameter / 3GPP S6a Interfaces.
![Shelly the PyHSS Snake](https://gitlab.com/nickvsnetworking/pyhss/raw/master/lib/shelly.png)

## Introduction
PyHSS is a simple Home Subscriber Server (HSS) used by LTE (4G) Evolved Packet Core (EPC) networks, written in Python.
3GPP network elements like the MME and PCRF communicate with the HSS via the [DIAMETER](https://tools.ietf.org/html/rfc6733) protocol, with some extensions defined by 3GPP.

## Implemented Responses 
 * Capabilities Exchange Answer (CEA)
 * Device Watchdog Answer (DWA)
 * Disconnect Peer Answer (DPA)
 * 3GPP Authentication Information Answer (AIA)
 * 3GPP Update Location Answer (ULA)

 
## Structure
The file *hss.py* runs a simple threaded Sockets based listener to take Diameter requests and send back Diameter responses.

Most of the heavy lifting in this is managed by the Diameter class, in *diameter.py*. This:
 * Decode incoming packets (Requests)(Returns AVPs as an array, called *avp*, and a Dict containing the packet variables (called *packet_vars*)
 * Generates responses (Answer messages) to Requests (when provided with the AVP and packet_vars of the original Request)
 * Generates Requests to send to other peers
 

 
## Subscriber Information Storage
MongoDB is used to store all the subscriber data (IMSI, APN Profiles & Crypto values for each subscriber)

Further information on setup is in *mongodb.yaml* file.

 
## Extending
To implement a new response is simply a matter of adding the *packet_vars['command_code']* and *packet_vars['ApplicationId']* to the if/elif loop in *hss.py*.
You can then access each of it's AVPs from the *avp* array, and the packet variables from the dictionary called *packet_vars*.
To add a new response you'd edit *diameter.py* and add a new function called Answer_YOURCOMMANDCODE, and build the AVPs and packet variables as required.

## Dependancies 
The Cryptographic stuff used to generate EUTRAN Authentication Vectors relies on the Python3 Crypto Module, which can be installed with 
```
pip3 install crypto
```

MongoDB backend relies on a MongoDB server to store the data on, and the Python libraries for pyyaml, mongo installed as:
```
pip3 install pyyaml mongo
```

The EUTRAN Authentication Vector generator is based on the one used in [Facebook Magma](https://github.com/facebookincubator/magma), which in turn is based off [OAI-CN](https://github.com/OPENAIRINTERFACE/openair-cn).

## About
This was written to fix a problem (VoLTE implementation on an EPC with a HSS that couldn't be easily customized), but will hopefully be of some use to the community.

Any contributions are welcome, just contact me and I'll give you access.

You can contact me at nick (at) nickvsnetworking.com or via my blog at [nickvsnetworking.com](https://nickvsnetworking.com)
