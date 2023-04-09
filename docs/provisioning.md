# PyHSS API Service

Using the PyHSS API we can provision objects into the HSS.

**Note:** Complete documentation on using every API Ednpoint on the HSS is included in the generated Swagger documentation on the `/docs/` endpoint, this doc you're reading now is just an a quick-start guide.

General flow to setup network:
 * Define Charging Rules & TFTs (If using dedicated bearers)
 * Define APNs

General flow to setup subscriber for access to data services:
 * Define SIM Card data in AuC
 * Define Subscriber w allowed APNs & AMBRs

General flow to setup subscriber for access to voice services:
 * Define IMS Subscriber w allowed Sh Profile & iFC Template


### Define Subscriber AuC Object
The AuC Objects store information about the SIMs deployed in the network, it's up to you how much information you want to store for each SIM, PyHSS supports storing pretty much all of the key data for OTA, eSIM / SMDP, etc, however these fields are optional.

At a minimum you will need to specify the OPc/Ki & AMF of the card.

If your data output only include the OP you can use the `CryptoTool.py` from the `lib` folder to convert the OP values into OPc values.

```shell
curl -X 'PUT' \
  'http://10.97.0.36:8080/auc/' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
    "ki": "11111111111111111111111111111111",
    "opc": "11111111111111111111111111111111",
    "amf": "8000"
  }'
```



### Define Subscriber for EPC Access
This defines IMSI 001010000000001 with access to APN with APN_ID 1 & APN_ID 2, where the APN with APN_ID 1 is the default APN for the subscriber. The AMBR values allow for 9999999 bytes per second (~8Mbps).
```shell
curl -X 'PUT' \
  'http://10.97.0.36:8080/subscriber/' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "imsi": "362300000000301",
  "enabled": true,
  "auc_id": 1,
  "default_apn": 1,
  "apn_list": "1",
  "msisdn": "599416501",
  "ue_ambr_dl": 9999999,
  "ue_ambr_ul": 9999999,
  "nam": 0,
  "subscribed_rau_tau_timer": 0
}'
```

### Define Subscriber for IMS Access
This defines a subscriber for access to the IMS.

Multiple MSISDNs can be defined as comma separated values in `msisdn_list` as required.

The Sh profile will need to be updated with a valid Sh profile for the sub.
```shell
curl -X 'PUT' \
  'http://10.97.0.36:8080/ims_subscriber/' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "msisdn": "12341235",
  "msisdn_list": "12341235",
  "imsi": "001010000000002",
  "ifc_path": "string",
  "sh_profile": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><simservs>Your XCAP Data...</simservs>"
}'
```