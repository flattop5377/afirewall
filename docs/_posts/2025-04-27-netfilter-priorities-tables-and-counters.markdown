---
layout: post
title:  "Netfilter Priorities, Tables, and Counters"
date:   2025-04-27 11:30:18 -0600
categories: afirewall update
---

## Priorities

afirewall places most of it's filtering rules at priority 10. Then at priority 20, it has a default policy of deny.

The intention is that afirewall doesn't interfere with other netfilter rulesets.

Netfilter processes priorities in numerical order: 10 before 20, and so on.

## Tables

afirewall uses two tables per protocol. For example ipv4 has an inbound table and an outbound table.  ipv6 also has one inbound and one outbound table.o

```
table ip a-firewall-inbound-ipv4
table ip a-firewall-outbound-ipv4
table ip a-firewall-inbound-ipv6
table ip a-firewall-outbound-ipv6
```

## Counters

Some rules have counters.

```
$ sudo nft list counters
```
ICMP Counters:
  * table ip a-firewall-inbound-ipv4
    * NUMBER_OF_SPOOFS_DROPPED
    * NUMBER_OF_INVALID_FLAGS_DROPPED
    * NUMBER_OF_FRAGMENTS_DROPPED
    * NUMBER_OF_PORT_ZERO_SEGMENTS_DROPPED
  * table ip a-firewall-outbound-ipv4
    * NUMBER_OF_INVALID_FLAGS_DROPPED

To show inbound NUMBER_OF_SPOOFS_DROPPED

```
$ sudo nftp list counter counter ip a-firewall-inbound-ipv4 NUMBER_OF_SPOOFS_DROPPED
```
