# EIR


## Operating Modes

The Equipment Identity Register built into PyHSS supports matching in one of two modes.

**Exact Mode** matches based on an exact matching IMEI, and matching the IMSI if set.
Exact Mode is suited for IMEI/IMSI locking, to ensure a SIM is locked to a particular device, or to blacklist stolen devices.

**Regex Mode** matches based on Regex, this is suited for whitelisting IMEI prefixes for say, specific validated vendors.

## SIM Swap Webhook

To notify an external system that a subscriber has swapped the SIM into a different device.

``sim_swap_notify_webhook`` is an endpoint triggered when the subscriber inserts their SIM into a different device for the first time.

This requires ``imsi_imei_logging`` to be set.

## Device History

If ``imsi_imei_logging`` is set, then every unique IMSI / IMEI mapping is visible via the API.

## Config Example
```
eir:
  match_type: Exact   #Options are Exact Match or Regex
                      #Exact match matchesthe IMEI and IMSI if set
                      #Regex matches by Regex
  imsi_imei_logging: True    #Store current IMEI / IMSI pair in backend
```