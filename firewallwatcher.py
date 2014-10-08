#!/usr/bin/python
import re
import sys
import os
import iptc

## Create a set of IPs to not act on - like localhost and your own IP
donotact = set(['127.0.0.1', '72.62.75.6', '72.52.75.7'])

## Open the Apache Log
logfile = open("/var/log/apache2/access.log", "r")

## Make sure you're able to manipulate tables.
if not os.getuid() == 0:
  print "You must be root to use iptables."
  sys.exit(2)


## Get the list of already-firewalled hosts from the system
table = iptc.Table(iptc.Table.FILTER)
chain = iptc.Chain(table, 'immediate-block')
for ip in chain.rules:
  iptoadd = (ip.src.split('/')[0])  # have to strip whitespace and then add to the set
  donotact.add(iptoadd.strip())
  

## For each line in the Apache log, search for phpMyAdmin:
## TODO:  Replace with pulls from an indicator list
for line in logfile:
  if line.find('phpMyAdmin') != -1:
    lineip = str(line.split('-')[0])         ## Get the IP from the line and then strip it
    ipaddr = lineip.strip()
    if ipaddr.strip() in (donotact):         ## If the IP is already in the array not to act on,
     print "Already banned:", ipaddr         ## Don't act on it.
    else:
     rule = iptc.Rule()
     rule.src = (ipaddr)
     rule.target = iptc.Target(rule, "DROP")
     chain.insert_rule(rule)

logfile.close()
