---
layout: post
title:  "Netfilter Command Line Examples"
date:   2025-04-27 13:34:52 -0600
categories: afirewall examples
---
## Tables

afirewall uses up to four tables; two for each protocol family.

  * IPV4:
    * a-firewall-inbound-ipv4
    * a-firewall-outbound-ipv4
  * IPV6
    * a-firewall-inbound-ipv6
    * a-firewall-outbound-ipv6

To show netfilter's tables:

```
$ sudo nft list tables
```

afirewall chose to use ip instead of inet chains because many environments still only have ipv4 addresses, and there is no reason to configure ipv6 rules.

## Chains

afirewall has a chains in each table for each service: for example, ACCEPT_HTTP in the a-firewall-outbound-ipv4 table.

To list the chains in a family

```
$ sudo nft list chains ip
```

The last parameter is the netfilter protocol family.

## Rulesets

A chain has rules that make a ruleset.

To list rules in a chain

```
$ sudo nft list chain a-firewall-outbound-ipv4 ACCEPT_HTTP
```

Or you can list all the rulesets in a table.

```
$ sudo nft list table a-firewall-outbound-ipv4
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
