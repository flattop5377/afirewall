# A Pure Netfilter Filewall

*** Status: Pre-Alpha - Under Development ***

Open Issues: https://github.com/flattop5377/afirewall/issues

## What is it?

afirewall is a wrapper for a Netfilter firewall featuring:
  * Easy to read [TOML](https://toml.io/en/) configuration file
  * Easy to configure and maintain with [Ansible](https://ansible.com)
    * [ansible.builtin.lineinfile](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/lineinfile_module.html) can do all the configuration
  * Implements IPV4 and IPV6 rules
    * Restrict and limit ICMP traffic but still allow IP discovery and troubleshooting tools to operate
  * Automatically discover external network interface
  * Policy based firewall
    * DENY INBOUND and OUTBOUND traffic by default
      * SSH, DNS, DHCP, HTTP, and HTTPS are added as exceptions by the default configuration
    * Explicitly add exceptions
  * Set reasonable connection limits per source IP and per Service
  * Persist rules across reboots using netfilters-persistence

