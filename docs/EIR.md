# EIR


## Operating Modes

The Equipment Identity Register built into PyHSS supports matching in one of two modes, set by **regex_mode**.

In **Exact Mode** (``regex_mode: 0``) matches are based on an exact matching IMEI, and matching the IMSI if set (If IMSI is set to nothing (''), then only the IMEI is evaluated).

Exact Mode is suited for IMEI/IMSI locking, to ensure a SIM is locked to a particular device, or to blacklist stolen devices.

**Regex Mode** (``regex_mode: 1``) matches based on Regex, this is suited for whitelisting IMEI prefixes for say, specific validated vendors.

The **match_response_code** maps to the Equipment-Status AVP output, so specified values are:
 * 0 : 'Whitelist'
 * 1: 'Blacklist'
 * 2: 'Greylist'

Some end to end examples of this provisioned into the API:

### IMSI / IMEI Binding
```json
{
      'imei': '1234', 
      'imsi': '567',
      'regex_mode': 0, 
      'match_response_code': 0
}
```
If IMSI is equal to *567* and is in use in IMEI *1234*, then the response code returned is 0 (Whitelist).

### IMEI Matching (Blacklist lost / stolen devices)
```json
{
      'imei': '99881232',
      'imsi': '', 
      'regex_mode': 0, 
      'match_response_code': 1
}
```
If the IMEI is equal to 99881232 used with any IMSI, then the response code returned is 1 (Blacklist). This would be used for devices reported stolen.

### IMEI Prefix Match (Blacklist / Whitelist all devices of type)
```json
{
      'imei': '^666.*',
      'imsi': '', 
      'regex_mode': 1, 
      'match_response_code': 1
}
```
If the IMEI starts with 666, then the response code returned is 1 (Blacklist).

### IMEI & IMSI Regex Match
```json
{
      'imei': '^777.*',
      'imsi': '^1234123412341234$', 
      'regex_mode': 1, 
      'match_response_code': 2
}
```
If the IMEI starts with 777 and the IMSI is 1234123412341234 then return 2 (Greylist).


### No Match Behaviour
If there is no match from the backend, then the config parameter ``no_match_response`` dictates the response code returned.

## SIM Swap Webhook

To notify an external system that a subscriber has swapped the SIM into a different device.

``sim_swap_notify_webhook`` is an endpoint triggered when the subscriber inserts their SIM (IMSI) into a new device (IMEI) for the first time.

This requires ``imsi_imei_logging`` to be set to ``True``.

The Webhook is an HTTP POST sent to the ``sim_swap_notify_webhook`` URL, containing JSON of IMSI, IMEI and match_response_code sent asynchronously.

## Device History

If ``imsi_imei_logging`` is set, then every unique IMSI / IMEI mapping is visible via the API.

This also allows us to detect SIM Swap events.

## Config Example
```yaml
eir:
  imsi_imei_logging: True    #Store current IMEI / IMSI pair in backend
  sim_swap_notify_webhook:  http://localhost/webhook/
  no_match_response: 2       #Greylist
```
