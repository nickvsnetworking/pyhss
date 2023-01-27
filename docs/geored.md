# PyHSS - Geographic Redundancy

To allow PyHSS to be geographically distributed, the *geored* feature updates dynamic subscriber info (Serving MME, PCRF metadata & Serving-CSCF) across a cluster of PyHSS instances using the Restful API.

## Overview
When an Network Element begins serving a subscriber, it informs the network (HSS) of this.

 * For the MME the Update Location Request tells the HSS (PyHSS) that that MME is serving that subscriber.
 * For the PGW the Gx Credit Control Request Initial, informs the PCRF (PyHSS) that that PGW is serving that UE / APN.
 * For the IMS, the Server Assignment Request determines which S-CSCF should serve a user.

This means PyHSS knows for every sub:
 * Which MME is serving the Subscriber
 * Which PGW is serving each of the APNs (And the IP address allocated for each) for the Subscriber
 * Which S-CSCF is serving the IMS Subscriber

The problem is that with a geographically distributed HSS, by default, this information is not synchronized.

By adding the Geographic Redundancy Feature (geored) each PyHSS instance broadcasts and asynchronous API call to all the other PyHSS instances, to inform it of a serving node change.

This uses the same RESTful API described in the API docs.

## Configuration
The configuration is fairly simple;
```
## Geographic Redundancy Parameters
geored:
  enabled: False
  sync_actions: ['HSS', 'IMS', 'PCRF']    #What event actions should be synced
  sync_endpoints:                         #List of PyHSS API Endpoints to update
    - 'http://hss01:8080'
    - 'http://hss02:8080'
```

The `enabled` flag controls if the feature is enabled or not.

You may want to only sync certain events, for example you may want to only sync S6a data from the MME to the HSS, for this you'd only set the `sync_actions` list to include `HSS`.

Valid values are currently `HSS`, `IMS` and `PCRF`.

To list what endpoints you want to broadcast this to, you will need to enter each in `sync_endpoints` list, including `http://` or `https://` as required. URLs can be IP Addresses or Domain Names, and may optionally include the port.

If no port is specified, HTTP uses port 80, HTTPS uses port 443.

## Error Handling
As the API calls to the remote PyHSS instances are asynchronous, errors are logged but ignored.