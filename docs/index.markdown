---
# Feel free to add content and custom Front Matter to this file.
# To modify the layout, see https://jekyllrb.com/docs/themes/#overriding-theme-defaults

layout: home
---

# A Pure Netfilter Firewall

*** Status: Pre-Alpha - Under Development ***

[Open Issues](https://github.com/flattop5377/afirewall/issues)

## What is it?

afirewall is a wrapper for a Netfilter firewall featuring:
  * Easy to read [TOML](https://toml.io/en/) configuration file
  * Easy to configure and maintain with [Ansible](https://ansible.com)
    * [ansible.builtin.lineinfile](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/lineinfile_module.html) can do all the configuration
  * Implements IPV4 and IPV6 rules
    * Restrict and limit ICMP traffic but still allow IP discovery and troubleshooting tools to operate
  * Automatically discover the external network interface
  * Policy based firewall
    * DENY INBOUND and OUTBOUND traffic by default
      * SSH, DNS, DHCP, HTTP, and HTTPS are added as exceptions by the default configuration
    * Explicitly add exceptions
  * Set reasonable connection limits per source IP and per Service
  * Persist rules across reboots using netfilters-persistence

## Installation

[Debian (APT) Package Repository](https://wiki.debian.org/DebianRepository)
  * [Repository Signature Key](https://raw.githubusercontent.com/flattop5377/debrepo/refs/heads/master/conf/flattop5377.public.asc)
  * /etc/apt/sources.list line: deb https://raw.githubusercontent.com/flattop5377/debrepo/master main
  * [Sample Configuration](https://raw.githubusercontent.com/flattop5377/debrepo/refs/heads/master/conf/flattop5377.sources) to save in /etc/apt/sources.list.d/flattop5377.sources

## Configuration

To enable or disable a service, edit the lines in /etc/afirewall/afirewall.conf. Inbound services are completely separate from outbound, so make sure to enable the appropriate direction of traffic. If the services is not listed there, then submit an issue or bravely explore the /etc/afirewall/templates directory and try to figure out the complex syntax of nft...

## Thank You

A special thank you to:
  * Firewall Influences:
    * [Advanced Policy Firewall](https://www.rfxn.com/projects/advanced-policy-firewall/)
    * [SoByte](https://www.sobyte.net/post/2022-04/understanding-netfilter-and-iptables/)

  * Debian Packaging:
    * [sigxcpu.org](https://honk.sigxcpu.org/piki/development/debian_packages_in_git/)
    * [eyrie.org](https://www.eyrie.org/~eagle/notes/debian/git.html)
    * [debian.org](https://www.debian.org/doc/manuals/debmake-doc/index.en.html)

