---
layout: page
title: About
permalink: /about/
---

## Easy to use on a VPS
I needed a pure netfilter firewall without iptables that I could configure
easily with Ansible.  Since most servers I use are virtual private servers
(VPS) from the usual providers, the firewall needs to be very simple to
install and configure.  The firewall also has to have default rules that
allow the server to work in a hosted environment with DHCP and DNS, and also
outbound HTTP/HTTPS for package installs and updates, with SSH allowed
inbound.

## Basic protection against brute force and DoS attacks
It seems like any server stood up as a VPS is immediately assaulted with bots
that attempt to brute force SSH logins, so I wanted to counters in the
firewall that limited SSH bots, but still allowed sane traffic, such as Ansible
to configure the VPS.

I also wanted limits on HTTP/HTTPS traffic since those ports are also under
constant assualt.

## Dump invalid traffic, but allow ICMP troubleshooting
I wanted a firewall that had strong rules for invalid traffic, including
filters for traffic that should never be on an interface.  The rules needed to
include filters for ICMP traffic, but still allow ICMP for network
troubleshooting.

## Use netfilter not iptables
The firewall needed to integrate easily with netfilter, and netfilter
persistence so that a minimum of additional configuration was needed to
maintain the firewall rules.  Since I may manually add rules, I also wanted the
filewall to operate at a priority where it wouldn't conflict with other
rules.

The reason for not wanting  iptables, is iptables is being replaced with
netfilter. Most firewalls still make use of iptables, and iptables doesn't
integrate with traffic flow and shaping tools as well as netfilter. Netfilter
is the future.
