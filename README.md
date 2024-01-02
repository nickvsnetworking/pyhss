# PyHSS

Python Home Subscriber Server implementing Diameter / 3GPP Interfaces.
![Shelly the PyHSS Snake](docs/images/shelly.png)

## Introduction
PyHSS is a Diameter Home Subscriber Server (HSS) and Subscriber Data Management solution, used for LTE (4G) Evolved Packet Core (EPC) networks, written in Python3.

This includes support for acting as:
 - Standard HSS
 - VoLTE HSS
 - Equipment Identity Register (EIR)
 - PCRF
 - Generate BSF Credentials
 - Gateway Mobile Location Centre 

Supported database backends include `MySQL`, `Postgresql`, `SQLite`, `Orcale`, `MS-SQL` and more, all provisioned through a Swagger based [RESTful API](docs/API.md) for easy, safe CRUD operations on the subscriber data.

The software supports full monitoring through `Prometheus`, and has been tested to over 1m subscribers.

To support redundancy, geographic redundancy clustering is supported to allow for multiple instances running together.

The underlying library - ``diameter.py`` can be easily worked with to add support other Diameter based interfaces / protocols.


## Implemented Responses 

* Diameter Base Protocol (Ie Device-Watchdog-Request, Capabilities-Exchange-Request)
* S6a - MME / HSS Authentication of Subscribers (Ie Authentication-Information-Request, Update-Location-Request)
* S13 - MME to EIR verification of devices (Ie ME-Identity-Check-Request)
* Cx - For P/S/I/E-CSCF Authentication and Routing (Ie User-Authentication-Request, Location-Information-Request)
* SLh - For Location of Subscriber MME from GMLC (Ie LCS-Routing-Info-Answer Request)
* Sh - For Application Servers to IMS & XCAP Data
* Zh/Zn - For generating GBA Credentials
* Gx Credit Control Answer / Re-Auth Request including installing Charging Rules on demand


## Usage

Basic configuration is set in the ``config.yaml`` file,

You will need to set the IP address to bind to (IPv4 or IPv6), the Diameter hostname, realm, your PLMN and transport type to use (SCTP or TCP).

The diameter service runs in a trusting mode allowing Diameter connections from any other Diameter hosts.

To perform as a functioning HSS, the following services must be run as a minimum:
- diameterService.py
- hssService.py

If you're provisioning the HSS for the first time, you'll also want to run:
 - apiService.py

The rest of the services aren't strictly necessary, however your own configuration will dictate whether or not they are required.

## Structure

PyHSS uses a queued microservices model. Each service performs a specific set of tasks, and uses redis messages to communicate with other services.

The following services make up PyHSS:
 - diameterService.py: Handles receiving and sending of diameter messages, and diameter client connection state.
 - hssService.py: Provides decoding and encoding of diameter requests and responses, as well as logic to perform as a HSS.
 - apiService.py: Provides the API, to allow management of PyHSS.
 - georedService.py: Sends georaphic redundancy messages to geored peers when defined. Also handles webhook messages.
 - logService.py: Handles logging for all services.
 - metricService.py: Exposes prometheus metrics from other services.
 
## Subscriber Information Storage

Subscriber data (IMSI, APN Profiles & Crypto values for each subscriber) are stored in a SQL backend, (See [databases](docs/databases.md) for more info) which can be interfaced with a number of different ways.

The [RESTful API](docs/API.md) allows for easy, safe CRUD operations on the subscriber data.

If REST isn't your jam and you instead want to interact directly with Python, `database.py` can be imported into your project and contains all the same hooks as the API.

## Installation
Dependencies can be installed using Pip3:

```shell
pip3 install -r requirements.txt
```

PyHSS also requires [Redis 7.0.0](https://redis.io/docs/getting-started/installation/install-redis-on-linux/) or above.

Then after setting up the config, you can fire up the necessary PyHSS services by running:
```shell
python3 diameterService.py
python3 hssService.py
python3 apiService.py
```

All going well you'll have a functioning HSS at this point. For production use, systemd scripts are located in `./systemd`
PyHSS API uses Flask, and can be configured with your favourite WSGI server.

To get everything more production ready checkout [Monit with PyHSS](docs/monit.md) for more info.

## Statistics

Historically stats were collected through Redis counters and exposed via an SNMP service, this feature has been left for backward compatibility, but now Prometheus is the recommended method for collecting metrics going forward.

More info about the legacy monitoring the system is available in [SNMP Readme](docs/monitoring.md).

## About

This software was written to address the limited options for lightweight HSS platforms out there, particularly those implementing IMS HSS functionality.

It is now deployed by several mid-tier operators, private LTE networks and lab networks worldwide.

Any contributions are welcome, just submit a PR or contact me.

You can contact me at nick (at) nickvsnetworking.com or via my blog at [nickvsnetworking.com](https://nickvsnetworking.com)
