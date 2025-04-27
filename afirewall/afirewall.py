#!/usr/bin/python3
from enum import Enum
from ipaddress import ip_address, ip_network
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

import argparse
import os
import re
import shutil
import subprocess
import sys

class Interface(object):
   def __init__(self, address, network, device, family):
      self.address = ip_address(address)
      self.network = ip_network(network, strict=False)
      self.device = device
      self.family = Family(family)
   def __repr__(self):
      return "Interface()"
   def __str__(self):
      return "Interface({family}, {address}, {network}, {device})".format(family=self.family, address=self.address, network=self.network, device=self.device)

class Family(Enum):
   IPV4 = 1
   IPV6 = 2
   LO = 3

IPV4_ADDRESS_REGEX_PATTERN = '.*src ([0-9\.]+) .*'
IPV4_DEVICE_REGEX_PATTERN = '.*dev ([0-9a-zA-Z]+) .*'
IPV6_ADDRESS_REGEX_PATTERN = '.*src ([0-9a-f:]+) .*'
IPV6_DEVICE_REGEX_PATTERN = '.*dev ([0-9a-f:]+) .*'

def stop():
   subprocess.run(args=[args.nft, 'delete', 'table', 'ip', 'a-firewall-inbound-ipv4'], capture_output=True, encoding='UTF-8')
   subprocess.run(args=[args.nft, 'delete', 'table', 'ip', 'a-firewall-outbound-ipv4'], capture_output=True, encoding='UTF-8')
   subprocess.run(args=[args.nft, 'delete', 'table', 'ip6', 'a-firewall-inbound-ipv6'], capture_output=True, encoding='UTF-8')
   subprocess.run(args=[args.nft, 'delete', 'table', 'ip6', 'a-firewall-outbound-ipv6'], capture_output=True, encoding='UTF-8')

def start(template_directory, interface, config):
   nft_input = test(template_directory, interface, config)
   nft_result = subprocess.run(args=[args.nft, '-f', nft_input], capture_output=True, encoding='UTF-8')

def test(template_directory, interface, config):
   nft_input = process_scripts(template_directory, interface, config)
   if nft_input != None:
      nft_result = subprocess.run(args=[args.nft, '-c', '-f',  nft_input], capture_output=True, encoding='UTF-8')
      if nft_result.returncode != 0:
         sys.exit('NFT syntax validation failed on ' + interface.family.name + ': ' + nft_result.stderr)
      return nft_input

def get_spoofed_networks(base_directory, interface):
   filename = base_directory + '/lists/spoofed_' + interface.family.name + '_networks.list'
   local_network = interface.network
   spoofed_networks  = []
   if interface.family == Family.IPV4:
      with open(filename) as file:
         for line in file:
            li = line.strip()
            if not li.startswith('#'):
               if interface.family == Family.IPV4:
                  match = re.search('([0-9\./]+)', li)
               elif interface.family == Family.IPV6:
                  match = re.search('([0-9a-f:/]+)', li)
               list_network = ip_network(match.group(1))
               if local_network.subnet_of(list_network):
                   for network in list_network.address_exclude(local_network):
                     spoofed_networks.append(network)
               else:
                  spoofed_networks.append(list_network)
   return spoofed_networks

def process_scripts(base_directory, interface, config):
   env = Environment(
      loader = FileSystemLoader([base_directory + '/templates', './templates'])
   )

   template_name = "{family}/base.rules".format(family=interface.family.name.lower());
   output_name = base_directory + "/" + interface.family.name.lower() + ".nft"

   spoofed_networks = get_spoofed_networks(base_directory, interface)

   try:
      template = env.get_template(template_name)
   except TemplateNotFound as e:
       sys.exit('Template not found: ' + e.message)

   try:
      template.stream({
               'EXTERNAL_DEVICE': interface.device, 
               'EXTERNAL_ADDRESS': interface.address, 
               'LOCAL_NETWORK': interface.network, 
               'SPOOFED_NETWORKS': spoofed_networks, 
               'inbound': config['inbound'],
               'outbound': config['outbound']
            }).dump(output_name)
   except FileNotFoundError as e:
      sys.exit('Unable to write a pure NetFilters Firewall for Linux rules to ' + output_name + ' because: ' + e.message)
   except TemplateNotFound as e:
      sys.exit('Unable to find included template ' + e.message)

   return output_name

def get_external_interface_address_or_device(destination, regex):
   ip_route = subprocess.run(args=[args.ip, '-o', 'route', 'get', 'to', destination], capture_output=True, encoding='UTF-8')
   match = re.search(regex, ip_route.stdout)
   if match is None: return None
   return match.group(1)

def get_external_ipv4_network(device):
   try:
      ip_ad_show = subprocess.run(args=[args.ip, '-o', '-f', 'inet', 'ad', 'show', device], capture_output=True, encoding='UTF-8')
      match = re.search('.*inet ([0-9\./]+) .*', ip_ad_show.stdout)
      if match is None: sys.exit('Failed to find local IPV4 network in: ' + ip_ad_show.stdout)
      return match.group(1)
   except TypeError:
      return None

def get_external_ipv6_network(device):
   try:
      ip_ad_show = subprocess.run(args=[args.ip, '-o', '-f', 'inet6', 'ad', 'show', device], capture_output=True, encoding='UTF-8')
      match = re.search('.*inet ([0-9\./]+) .*', ip_ad_show.stdout)
      if match is None: sys.exit('Failed to find local IPV4 network in: ' + ip_ad_show.stdout)
      return match.group(1)
   except TypeError:
      return None

def get_external_ipv4_interface(destination):
   address = get_external_interface_address_or_device(destination, IPV4_ADDRESS_REGEX_PATTERN)
   device = get_external_interface_address_or_device(destination, IPV4_DEVICE_REGEX_PATTERN)
   network = get_external_ipv4_network(device)
   interface = Interface(address, network, device, Family.IPV4)
   return interface

def get_external_ipv6_interface(destination):
   address = get_external_interface_address_or_device(destination, IPV6_ADDRESS_REGEX_PATTERN)
   device = get_external_interface_address_or_device(destination, IPV6_DEVICE_REGEX_PATTERN)
   network = get_external_ipv6_network(device)
   try:
     interface = Interface(address, network, device, Family.IPV6)
   except ValueError:
     interface = None
   return interface

def get_parser():
   parser = argparse.ArgumentParser(description='Netfilter Persistence Plugin that configures a pure NetFilters Firewall for Linux')
   parser.add_argument('command', choices=['start', 'restart', 'reload', 'force-reload', 'stop', 'flush', 'save', 'test'], help='Manage netfilter rules for a firewall')
   parser.add_argument('-nft', help='full path to nft - default /usr/sbin/nft', default='/usr/sbin/nft')
   parser.add_argument('-ip', help='full path to ip - default /usr/bin/ip', default='/usr/bin/ip')
   parser.add_argument('-ipv4dest', help='destination used to find the external ipv4 address and device - default 8.8.8.8', default='8.8.8.8')
   parser.add_argument('-ipv6dest', help='destination used to find the external ipv6 address and device - default 2001:4860:4860:0:0:0:0:8888', default='2001:4860:4860:0:0:0:0:8888')
   parser.add_argument('-b', '--basedir', help='path to the base configuration directory - default /etc/afirewall', default='/etc/afirewall')
   return parser

def parse_arguments():
   parser = get_parser()
   args = parser.parse_args()

   if not shutil.which(args.nft, mode=os.X_OK): sys.exit(args.nft + ' is not executable')
   nft_completed = subprocess.run(args=[args.nft, '-V'], capture_output=True, encoding='UTF-8')
   pattern = re.compile('nftables')
   if not pattern.match(nft_completed.stdout): sys.exit(args.nft + ' doesn\'t appear to be nft?')

   if not shutil.which(args.ip, mode=os.X_OK): sys.exit(args.ip + ' is not executable')
   ip_completed = subprocess.run(args=[args.ip, '-V'], capture_output=True, encoding='UTF-8')
   pattern = re.compile('ip utility.*')
   if not pattern.match(ip_completed.stdout): sys.exit(args.ip + ' doesn\'t appear to be ip?')

   if not os.access(args.basedir, mode=os.R_OK): sys.exit('Base configuration directory ' + args.basedir + ' can\'t be opened')

   if not os.access(args.basedir + '/afirewall.conf', mode=os.R_OK): sys.exit('Configuration file ' + args.basedir + '/afirewall.conf can\'t be opened')

   return args

def branch(tree, vector, value):
   key = vector[0]
   if len(vector) == 1:
      if value == 'true' or value.lower() == 'enable':
         tree[key] = True
      elif value == 'false' or value.lower() == 'disable':
         tree[key] = False
      else:
         sys.exit('Invalid value, must be <true, enable, false, disable> in afirewall.conf: ' + value);
   else:
      tree[key] = branch(tree[key] if key in tree else {}, vector[1:], value)
   return tree

def get_configuration():
   config = {}
   with open(args.basedir + '/afirewall.conf', 'r') as file:
      for line in file:
         li = re.sub('\s+', '', line)
         li = li.lower()
         if not li.startswith('#') and li.find(':') != -1:
            kv = li.split(':')
            config = branch(config, kv[0].split('.'), kv[1])
   return config

def get_interfaces():
   interfaces = []
   interface = get_external_ipv4_interface(args.ipv4dest)
   if interface != None:
      interfaces.append(interface)
   else:
      print('Warning: no IPv4 interface found.  No firewall will be started for IPv4')
      print('There was no valid route to ' + args.ipv4dest)
   interface = get_external_ipv6_interface(args.ipv6dest)
   if interface != None:
      interfaces.append(interface)
   else:
      print('Warning: no IPv6 interface found.  No firewall will be started for IPv6')
      print('There was no valid route to ' + args.ipv6dest)

   return interfaces

if __name__ == "__main__":
   if os.geteuid() != 0: sys.exit('Root permissions required.')

   args = parse_arguments()
   config = get_configuration()
   interfaces = get_interfaces()

   match args.command:
      case 'start' | 'restart' | 'reload' | 'force-reload' | 'save':
         stop()
         for interface in interfaces:
            start(args.basedir, interface, config)
      case 'stop' | 'flush':
         stop()
      case 'test':
         for interface in interfaces:
            test(args.basedir, interface, config)
