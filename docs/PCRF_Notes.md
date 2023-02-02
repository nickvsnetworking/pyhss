# PCRF


## Basic Operation
The Gx interface provides the PGW with Charging Rules that define how traffic of a particular type should be treated.

When a subscriber attaches to the network, the PGW sends a Gx Credit Control Request to the PCRF, and the PCRF returns the policies that govern how the traffic should be handled and treated.

![PGW Actions on Charging Rules](https://i0.wp.com/nickvsnetworking.com/wp-content/uploads/2023/01/Blog-Examples-Charging-Rule.png)


## Defining Charging Rules
### Policy

In cellular world, as in law, policy is the rules.

For us some examples of policy could be a “fair use policy” to limit customer usage to acceptable levels, but it can also be promotional packages, services like “free Spotify” packages, “Voice call priority” or “unmetered access to Nick’s Blog and maximum priority” packages, can be offered to customers.

All of these are examples of policy, and to make them work we need to target which subscribers and traffic we want to apply the policy to, and then apply the policy.

### Charging Rules
Charging Rules are where the policy actually gets applied and the magic happens.

It’s where we take our policy and turn it into actionable stuff for the cellular world.

Let’s take an example of “unmetered access to Nick’s Blog and maximum priority” as something we want to offer in all our cellular plans, to provide access that doesn’t come out of your regular usage, as well as provide QCI 5 (Highest non dedicated QoS) to this traffic.

To achieve this we need to do 3 things:

 * Profile the traffic going to this website (so we capture this traffic and not regular other internet traffic)
 * Charge it differently – So it’s not coming from the subscriber’s regular balance
 * Up the QoS (QCI) on this traffic to ensure it’s high priority compared to the other traffic on the network

So how do we do that?

### Profiling Traffic
So the first step we need to take in providing free access to this website is to filter out traffic to this website, from the traffic not going to this website.

Let’s imagine that this website is hosted on a single machine with the IP 1.2.3.4, and it serves traffic on TCP port 443. This is where IPFilterRules (aka TFTs or “Traffic Flow Templates”) and the Flow-Description AVP come into play.

IPFilterRules are defined in the Diameter Base Protocol (IETF RFC 6733), where we can learn the basics of encoding them,

They take the format:

```action dir proto from src to dst```

The action is fairly simple, for all our Dedicated Bearer needs, and the Flow-Description AVP, the action is going to be permit. We’re not blocking here.

The direction (dir) in our case is either in or out, from the perspective of the UE.

Next up is the protocol number (proto), as defined by IANA, but chances are you’ll be using 17 (UDP) or 6 (TCP).

The from value is followed by an IP address with an optional subnet mask in CIDR format, for example from 10.45.0.0/16 would match everything in the 10.45.0.0/16 network.

Following from you can also specify the port you want the rule to apply to, or, a range of ports.

Like the from, the to is encoded in the same way, with either a single IP, or a subnet, and optional ports specified.

And that’s it!

So let’s create a rule that matches all traffic to our website hosted on 1.2.3.4 TCP port 443,

```shell
permit out 6 from 1.2.3.4 443 to any 1-65535
permit out 6 from any 1-65535 to 1.2.3.4 443
```

All this info gets put into the Flow-Information AVPs:
![Flow information AVP](https://i0.wp.com/nickvsnetworking.com/wp-content/uploads/2023/01/image-1.png)

With the above, any traffic going to/from 1.23.4 on port 443, will match this rule (unless there’s another rule with a higher precedence value).

### Charging Actions
So with our traffic profiled, the next question is what actions are we going to take, well there’s two, we’re going to provide unmetered access to the profiled traffic, and we’re going to use QCI 4 for the traffic (because you’ll need a guaranteed bit rate bearer to access!).

### Charging-Group for Profiled Traffic
To allow for Zero Rating for traffic matching this rule, we’ll need to use a different Rating Group.

Let’s imagine our default rating group for data is 10000, then any normal traffic going to the OCS will use rating group 10000, and the OCS will apply the specific rates and policies based on that.

Rating Groups are defined in the OCS, and dictate what rates get applied to what Rating Groups.

For us, our default rating group will be charged at the normal rates, but we can define a rating group value of 4000, and set the OCS to provide unlimited traffic to any Credit-Control-Requests that come in with Rating Group 4000.

![Rating Group 4000](https://i0.wp.com/nickvsnetworking.com/wp-content/uploads/2023/01/image-3.png)

*This is how operators provide services like “Unlimited Facebook” for example, a Charging Rule matches the traffic to Facebook based on TFTs, and then the Rating Group is set differently to the default rating group, and the OCS just allows all traffic on that rating group, regardless of how much is consumed.*

Inside our Charging-Rule-Definition, we populate the Rating-Group AVP to define what Rating Group we’re going to use.


### Setting QoS for Profiled Traffic
The QoS Description AVP defines which QoS parameters (QCI / ARP / Guaranteed & Maximum Bandwidth) should be applied to the traffic that matches the rules we just defined.

As mentioned at the start, we’ll use QCI 4 for this traffic, and allocate MBR/GBR values for this traffic.

![QoS-Information AVP](https://i0.wp.com/nickvsnetworking.com/wp-content/uploads/2023/01/image.png)


### Putting it Together – The Charging Rule
So with our TFTs defined to match the traffic, our Rating Group to charge the traffic and our QoS to apply to the traffic, we’re ready to put the whole thing together.

So here it is, our “Free NVN” rule:
![Charging-Rule definitions in PCRF](https://i0.wp.com/nickvsnetworking.com/wp-content/uploads/2023/01/image-4.png)

[Reference PCAP](https://nickvsnetworking.com/wp-content/uploads/2023/01/Diameter_Gx_ChargingRule_Install.pcap)


## Charging Rules in the PyHSS PCRF Function

PyHSS includes a PCRF function to allow it to serve the Gx interface and handle PCRF requests.

To begin with via the [RESTful API](api.md) you'll need to define your TFTs.

TFTs will match based on the TFT-Group ID, this means we can have multiple TFTs associated with one Charging Rule.

*The below examples use Python3 and the Requests library to interact with the API*

### Defining TFT via the API

To begin with we'll define the two TFTs we used earlier, via the API, and group them together with `tft_group_id` 1:

```python
    import requests
    base_url = "http://your_hss_ip:5000"
    headers = {"Content-Type": "application/json"}
    #Define TFTs
    tft_template1 = {
        'tft_group_id' : 1,
        'tft_string' : 'permit out 6 from 1.2.3.4 443 to any 1-65535',
        'direction' : 1
    }
    tft_template2 = {
        'tft_group_id' : 1,
        'tft_string' : 'permit out 6 from any 1-65535 to 1.2.3.4 443',
        'direction' : 2
    }
    print("Creating TFTs")
    r = requests.put(str(base_url) + '/tft/', data=json.dumps(tft_template1), headers=headers)
    r = requests.put(str(base_url) + '/tft/', data=json.dumps(tft_template2), headers=headers)    
```

### Define Charging Rule
Next up we'll define a Charging Rule to match this traffic.

We'll call the rule "free_nvn" and set the QCI to 4, the ARP Vulnerability / Capability as required, and the MBR and GBR if using a GBR QCI (GBR QCI values are typically 1-4).

We'll also need to specify the `tft_group_id` as this will reference 

```python
    charging_rule = {
        'rule_name' : 'free_NVN',
        'qci' : 4,
        'arp_priority' : 5,
        'arp_preemption_capability' : True,
        'arp_preemption_vulnerability' : False,
        'mbr_dl' : 128000,
        'mbr_ul' : 128000,
        'gbr_dl' : 128000,
        'gbr_ul' : 128000,
        'tft_group_id' : 1,
        'precedence' : 100,
        'rating_group' : 20000
        }
    print("Creating Charging Rule A")
    r = requests.put(str(base_url) + '/charging_rule/', data=json.dumps(charging_rule_template), headers=headers)
    print("Created Charging Rule ID: " + str(r.json()['charging_rule_id']))
```

Now we've created the Charging Rule, we can just add it to the charging_rule_list object on the APNs we wish to apply it to. Let's assume that the Charging Rule ID is 10 and it's the only charging rule we want to apply onto the APN "Internet":

```python
    template_data = {
        "apn": "UnitTest",
        "pgw_address": "10.98.0.20",
        "sgw_address": "10.98.0.10",
        "charging_characteristics": "0800",
        "apn_ambr_dl": 99999,
        "apn_ambr_ul": 99999,
        "qci": 7,
        "ip_version": 0,
        "arp_priority": 1,
        "arp_preemption_capability": True,
        "arp_preemption_vulnerability": True,
        "charging_rule_list" : '10',
        }

    r = requests.put(str(base_url) + '/apn/', data=json.dumps(template_data), headers=headers)
```

In the `charging_rule_list` object wen can add additional comma separated Charging Rule IDs for other defined Charging Rules. (Setting the value to None will result in no Charging Rules being installed in the Credit Control Answer)

Then when a subscriber attaches to one of these APNs, the Charging Rules listed in the `charging_rule_list` will be returned in the *Gx Credit Control Answer* and installed into the PCEF in the PGW.
