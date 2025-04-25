# A pure Netfilter Firewall on Linux
## Goals
   - Be resonably secure
   - Be easy to install, configure, and maintain
   - Be Ansible friendly
   - Use common tools and formats
## Description
A firewall that uses nft only, is easily configured through Ansible, has some sane defaults for security, doesn't restrict the full flexibility of other pure netfilter firewall configuration, uses common or simple tools and formats, and integrates nicely with existing networking architecture.
## Installation
### Ansible
## Developer instructions
### Python environment setup
```
$ python3 -m venv .venv
$ . .venv/bin/activate
$ python3 -m pip install -r requirements.txt
```
### Tests
```
$ python3 -m unittest discover
```
