#!/usr/bin/python3
"""RZFeeser | rzfeeser@alta3.com
now that we have a json pcap, we are playing with mechanisms for scanning that JSON for data we want...
Example: 'How many times is Cisco in eth.src_tree vs eth.dst_tree'"""

import json

cisco_eth_src = 0
cisco_eth_dst = 0

# archives/2020-09-04_16-49-17/00cafe673248/trace_avay_containing_00cafe673248.json
# archives/2020-09-04_16-49-17/68bc0c7efcbf/trace_avay_containing_68bc0c7efcbf.json

with open("archives/2020-09-04_16-49-17/68bc0c7efcbf/trace_avay_containing_68bc0c7efcbf.json", "r") as jfile:
    jfile = json.loads(jfile.read())

for packet in jfile:
    
    if "Cisco" or "cisco" or "Avaya" in packet.get("_source").get("_layers").get("eth").get("eth.src_tree").get("eth.addr_resolved"):
        cisco_eth_src = cisco_eth_src + 1 # if you saw Cisco in the name, then add one to the counter
                                          # shorthand ver: cisco_eth_src += 1
    
    if "Cisco" or "cisco" or "Avaya" in packet.get("_source").get("_layers").get("eth").get("eth.dst_tree").get("eth.addr_resolved"):
        cisco_eth_dst = cisco_eth_dst + 1 # if you saw a Cisco in the name, then add one to the counter

print(f"A Cisco device was detected in the source mac {cisco_eth_src} number of times")
print(f"A Cisco device was deteced in the dest mac {cisco_eth_dst} number of times")
