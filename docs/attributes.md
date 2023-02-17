## PyHSS Attributes

Because sometimes you want to add extra stuff onto Subscribers, we have the Attributes API which allows you to store extra stuff to do with a subscriber along side the Subscriber.

### Adding an Attribute to a Subscriber

You can add as many attributes as needed to a Subscriber,

For example to store a `CustomerName` alongside Subscriber 1, with a value of "Nick" we'd send an HTTP PUT to `/subscriber_attributes/` with the below JSON Body:

```
{
  "subscriber_id": 1,
  "key": "CustomerName",
  "value": "Nick"
}
```

We can add as many attributes as needed.

Each attribute is given a `subscriber_attributes_id` which we can use to edit/delete the attribute using the `DELETE` and `PATCH` endpoints.

### Retrieving all Attributes

From the `subscriber_attributes` endpoint we can extract all the attributes for a particular `subscriber_id`.

We can also get this information in the `/subscriber/imsi/` and `/subscriber/msisdn` endpoints under the `attributes` key:

```
{
  "default_apn": 1,
  "subscriber_id": 1,
  "enabled": true,
  "msisdn": "123456",
  "ue_ambr_ul": 9999999,
  "subscribed_rau_tau_timer": 600,
  "serving_mme_timestamp": null,
  "imsi": "0010100000000101",
  "auc_id": 1,
  "apn_list": "1,2,3",
  "ue_ambr_dl": 9999999,
  "nam": 0,
  "serving_mme": null,
  "attributes": [
    {
      "subscriber_id": 1,
      "subscriber_attributes_id": 1,
      "value": "Nick",
      "key": "CustomerName"
    },
    {
      "subscriber_id": 1,
      "subscriber_attributes_id": 2,
      "value": "Nick",
      "key": "CustomerName"
    },
    {
      "subscriber_id": 1,
      "subscriber_attributes_id": 3,
      "value": "Nick",
      "key": "CustomerNamesdfsdf"
    },
    {
      "subscriber_id": 1,
      "subscriber_attributes_id": 4,
      "value": "Nick",
      "key": "asdfsdaf"
    },
    {
      "subscriber_id": 1,
      "subscriber_attributes_id": 5,
      "value": "gafdsa",
      "key": "dsfasdfsa"
    },
    {
      "subscriber_id": 1,
      "subscriber_attributes_id": 6,
      "value": "gafdsa",
      "key": "gasdfasfas"
    },
  ]
}
```