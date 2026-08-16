---
layout: home
title: A Pure Netfilter Firewall Wrapper
---

*** Status: Beta — feature complete, in production on the maintainer's own hosts ***

[Open Issues](https://github.com/flattop5377/afirewall/issues)

## What is it?

afirewall is a wrapper for a Netfilter firewall featuring:
  * Easy to read [TOML](https://toml.io/en/) configuration file
  * Easy to configure and maintain with [Ansible](https://ansible.com)
    * [ansible.builtin.lineinfile](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/lineinfile_module.html) can do all the configuration
  * Implements IPV4 and IPV6 rules
    * Restrict and limit ICMP traffic but still allow IP discovery and troubleshooting tools to operate
  * Automatically discover network interface(s)
  * Policy based firewall
    * DENY INBOUND and OUTBOUND traffic by default
      * SSH, DNS, DHCP, HTTP, and HTTPS are added as exceptions by the default configuration
    * Explicitly add exceptions
  * Set reasonable connection limits per source IP and per Service
  * Persist rules across reboots using netfilters-persistence

## Installation

The repository ships a **deb822 sources file with the signing key inside it**, so adding it is one
download rather than a key dance. Nothing has to be copied into `/etc/apt/trusted.gpg.d`, and
nothing is trusted repository-wide.

```sh
sudo curl -fsSL -o /etc/apt/sources.list.d/flattop5377.sources \
  https://raw.githubusercontent.com/flattop5377/debrepo/master/conf/flattop5377.sources
sudo apt update
sudo apt install afirewall
```

Check what you got before trusting it:

```sh
apt policy afirewall
apt-cache show afirewall | grep -E '^(Package|Version|Filename)'
```

### Which suite

The repository currently publishes **`bookworm` only**. On a newer Debian the sources file still
works — `afirewall` is `Architecture: all` and pure Python, so the codename in the path is a label
rather than a compatibility claim — but if you would rather be explicit, edit `Suites:` in the file
you just downloaded.

### If you prefer to write the file yourself

Use the deb822 format above rather than a one-line `deb` entry. A one-liner needs the suite and the
component and a `signed-by=` pointing at a key you have already installed, and getting any of the
three wrong produces an error about signatures rather than about the line you typed. The shipped
file carries the key inline and cannot be got wrong.

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
