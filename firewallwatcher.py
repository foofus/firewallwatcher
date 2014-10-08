#!/usr/bin/python
import re, sys, os, iptc

## Use the Apache logfile as source
with open('/var/log/apache2/access.log', 'rb') as logfile:

## Create a set of IPs to not act on - like localhost and your own IP
 donotact = set(['127.0.0.1', '72.62.75.6', '72.52.75.7'])

## Make sure you're able to manipulate tables.
 if not os.getuid() == 0:
   print 'You must be root to use iptables.'
   sys.exit(2)

## Get the list of already-firewalled hosts from the system
 table = iptc.Table(iptc.Table.FILTER)
 chain = iptc.Chain(table, 'immediate-block')
 for ip in chain.rules:
   iptoadd = ip.src.partition('/')[0]
   donotact.add(iptoadd)
  
## For each line in the Apache log, search for phpMyAdmin:
## TODO:  Replace with pulls from an indicator list
 for line in logfile:
   if 'phpMyAdmin' in line:
     lineip = line.partition('-')[0]
     ipaddr = lineip.strip()
     if ipaddr in donotact:                        ## If the IP is already in the array not to act on,
      print 'Already banned: {}'.format(ipaddr)    ## Do not act on it.
     else:
      rule = iptc.Rule()
      rule.src = ipaddr
      rule.target = iptc.Target(rule, 'DROP')
      chain.insert_rule(rule)
