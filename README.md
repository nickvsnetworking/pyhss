# PyHSS

Python Home Subscriber Server implementing Diameter / 3GPP S6a Interfaces.
![Shelly the PyHSS Snake](https://github.com/nickvsnetworking/pyhss/blob/master/lib/shelly.png?raw=true)

## Introduction
PyHSS is a Diameter Home Subscriber Server (HSS) and Subscriber Data Management solution, used for LTE (4G) Evolved Packet Core (EPC) networks, written in Python3.

This includes support for standard data subscribers over the S6a interface, VoLTE subscribers over the Cx, Sh and SLh interface, and to act as an EIR over the S13 interface

The underlying library - ``diameter.py`` provided here can be easily worked with to add support other Diameter based interfaces / protocols as required, for example to impliment a DRA or PCRF.

## Usage

Basic configuration is set in the ``config.yaml`` file,

You will need to set the IP address to bind to (IPv4 or IPv6), the Diameter hostname, realm, your PLMN and transport type to use (SCTP or TCP).

Then you will need to select a database backend to use. PyHSS supports many different backends and the datbase backend you use is up to you, premade configs exist for MongoDB, MSSQL, MySQL and Postgres.

Once the configuration is done you can run the HSS by running ``hss.py`` and the server will run using whichever transport (TCP/SCTP) you have selected.

## Implemented Responses 

* Diameter Base Protocol (Ie Device-Watchdog-Request, Capabilities-Exchange-Request)
* S6a - MME / HSS Authentication of Subscribers (Ie Authentication-Information-Request, Update-Location-Request)
* S13 - MME to EIR verification of devices (Ie ME-Identity-Check-Request)
* Cx - For P/S/I/E-CSCF Authentication and Routing (Ie User-Authentication-Request, Location-Information-Request)
* SLh - For Location of Subscriber MME from GMLC (Ie LCS-Routing-Info-Answer Request)
* Sh - For Application Servers to IMS & XCAP Data
* Zh/Zn - For generating GBA Credentials

 
## Structure

The file *hss.py* runs a threaded Sockets based listener (SCTP or TCP) to recieve Diameter requests, process them and send back Diameter responses.

Most of the heavy lifting in this is managed by the Diameter class, in ``diameter.py``. This:

 * Decodes incoming packets (Requests)(Returns AVPs as an array, called *avp*, and a Dict containing the packet variables (called *packet_vars*)
 * Generates responses (Answer messages) to Requests (when provided with the AVP and packet_vars of the original Request)
 * Generates Requests to send to other peers

 
## Subscriber Information Storage

Subscriber data (IMSI, APN Profiles & Crypto values for each subscriber) can be stored in a variety of different databases, such as MongoDB, MSSQL and MySQL, and can easily be extended to support other database backends and integrate with existing database schemas.

At the moment we're not shipping a database schema, and leaving it up to you how you store the data or in what format.
See [databases](docs/databases.md) for more info on how you can easily integrate into your existing database.

## Installation
Dependancies can be installed using Pip3:

```
pip3 install -r requirements.txt
```

Then after setting up the config, you can fire up the HSS itself by running:
```
python3 hss.py
```

All going well you'll have a functioning HSS at this point.

To get everything more production ready checkout [Monit with PyHSS](docs/monit.md) for more info.

## Statistics

If enabled, statistics are collected across threads using Redis.
These keys and values are then able to be read by an SNMP service - ``tools/snmp_service.py`` to expose these values to be read by an external NMS such as LibreNMS or Nagios.

More info about monitoring the system is available in [SNMP Readme](docs/monitoring.md).

## About

This software was written to address the limted options of free or lightweight HSS platforms out there, particularly those implimenting IMS HSS functionality.

It is now deployed by several mid-tier operators, private LTE networks and lab networks worldwide.

Any contributions are welcome, just submit a PR or contact me.

You can contact me at nick (at) nickvsnetworking.com or via my blog at [nickvsnetworking.com](https://nickvsnetworking.com)
