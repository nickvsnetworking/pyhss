# PyHSS

Python Home Subscriber Server implementing Diameter / 3GPP S6a Interfaces.
![Shelly the PyHSS Snake](https://gitlab.com/nickvsnetworking/pyhss/raw/master/lib/shelly.png)

## Introduction
PyHSS is a simple Home Subscriber Server (HSS) used by LTE (4G) Evolved Packet Core (EPC) networks, written in Python.
3GPP network elements like the MME, CSCFs and PCRF communicate with the HSS via the [DIAMETER](https://tools.ietf.org/html/rfc6733) protocol, with some extensions defined by 3GPP.

The underlying library - ``diameter.py`` can be easily worked with to impliment other Diameter based interfaces as required.

## Usage
Basic configuration is set in the ``config.yaml`` file,

You will need to set the IP address to bind to, the Diameter hostname, realm, your PLMN and transport type to use (SCTP or TCP).

Then you will need to select a database backend to use, such as MongoDB, MSSQL or MySQL.

Once the configuration is done you can run the HSS by running ``hss.py`` and the server will run using whichever transport (TCP/SCTP) you have selected.

## Implemented Responses 
 * Capabilities Exchange Answer (CEA)
 * Device Watchdog Answer (DWA)
 * Disconnect Peer Answer (DPA)
 * S6a Authentication Information Answer (AIA)
 * S6a Update Location Answer (ULA)
 * S6a Purge UE Answer (PUA)
 * S6a Notify Answer (NOA)
 * Cx Location Information Answer (LIA)
 * Cx User Authentication Answer (UAA)
 * Cx Server Assignment Answer (SAA)
 * Cx Multimedia Authentication Answer (MAA)
 * Cx Registration Termination Answer (RTA)
 * S13 - ME-Identity-Check Request

 
## Structure
The file *hss.py* runs a simple threaded Sockets based listener to take Diameter requests and send back Diameter responses.

Most of the heavy lifting in this is managed by the Diameter class, in ``diameter.py``. This:
 * Decode incoming packets (Requests)(Returns AVPs as an array, called *avp*, and a Dict containing the packet variables (called *packet_vars*)
 * Generates responses (Answer messages) to Requests (when provided with the AVP and packet_vars of the original Request)
 * Generates Requests to send to other peers
 

 
## Subscriber Information Storage
Subscriber data (IMSI, APN Profiles & Crypto values for each subscriber) can be stored in a variety of different databases, such as MongoDB, MSSQL and MySQL, and can easily be extended to support other database backends and integrate with existing database schemas.
See [databases](docs/databases.md) for more info.

## Statistics
If enabled, statistics are collected across threads using Redis.
These keys and values are then able to be read by an SNMP service - ``tools/snmp_service.py`` to expose these values to be read by an external NMS such as LibreNMS or Nagios.

More info available in [SNMP Readme](docs/SNMP_README.md).



## Dependancies 
The Cryptographic stuff used to generate EUTRAN Authentication Vectors relies on the Python3 Crypto Module, which can be installed with 
```
pip3 install crypto
pip3 install pyyaml
```

MongoDB backend relies on a MongoDB server to store the data on, and the Python libraries for pyyaml, mongo installed as:
```
pip3 install pyyaml mongo
```

The EUTRAN Authentication Vector generator is based on the one used in [Facebook Magma](https://github.com/facebookincubator/magma), which in turn is based off [OAI-CN](https://github.com/OPENAIRINTERFACE/openair-cn).

## About
This software was written to address the limted options of free or lightweight HSS platforms out there, particularly those implimenting IMS HSS functionality.

Any contributions are welcome, just submit a PR or contact me.

You can contact me at nick (at) nickvsnetworking.com or via my blog at [nickvsnetworking.com](https://nickvsnetworking.com)
