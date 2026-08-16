#!/usr/bin/python3
from enum import Enum
from ipaddress import ip_address, ip_network
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

import argparse
import glob
import json
import os
import pwd
import re
import shutil
import subprocess
import sys

def warn(message):
   """To stderr, so a warning survives having stdout piped somewhere and still reads in
   order beside the errors it sits between."""
   print('Warning: ' + message, file=sys.stderr)

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


def stop():
   subprocess.run(args=[args.nft, 'delete', 'table', 'ip', 'a-firewall-inbound-ipv4'], capture_output=True, encoding='UTF-8')
   subprocess.run(args=[args.nft, 'delete', 'table', 'ip', 'a-firewall-outbound-ipv4'], capture_output=True, encoding='UTF-8')
   subprocess.run(args=[args.nft, 'delete', 'table', 'ip6', 'a-firewall-inbound-ipv6'], capture_output=True, encoding='UTF-8')
   subprocess.run(args=[args.nft, 'delete', 'table', 'ip6', 'a-firewall-outbound-ipv6'], capture_output=True, encoding='UTF-8')

def start(nft_input):
   """Load a ruleset, and say so when it does not load.

   The return code used to go unread and stderr was captured and thrown away, so a load that
   failed printed 'Loading rules from ...' and exited 0 with the host unprotected. A firewall
   that cannot say whether it is running is worse than one that is plainly off."""
   nft_result = subprocess.run(args=[args.nft, '-f', nft_input], capture_output=True, encoding='UTF-8')
   if nft_result.returncode != 0:
      sys.exit('Failed to load ' + nft_input + ': ' + nft_result.stderr.strip())

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
   # Both families. This read used to be wrapped in `if interface.family == Family.IPV4`,
   # which meant ipv6 got an empty list however good its list file was - and the SPOOFING
   # chain it fed rendered with no rows at all, so ipv6 had no anti-spoofing and said
   # nothing about it.
   with open(filename) as file:
      for line in file:
         li = line.strip()
         # Blank lines too, not only comments: '' does not start with '#', and the search
         # below then returns None to have .group() called on it.
         if li and not li.startswith('#'):
            if interface.family == Family.IPV4:
               match = re.search(r'([0-9\./]+)', li)
            else:
               match = re.search(r'([0-9a-fA-F:/]+)', li)
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

def ip_json(*arguments):
   """Ask `ip` for structured output instead of parsing what it prints for humans.

   THIS REPLACED FOUR REGEXES AND THE BUG THEY HID. Interface discovery used to match `ip`'s
   human-readable output, and the IPv6 device pattern was `[0-9a-f:]+` - copied from the pattern for
   an IPv6 ADDRESS onto the field holding a DEVICE NAME. It cannot match `ens3`, `eth0`, `enp4s0` or
   any other normal interface, so IPv6 discovery returned nothing, `get_interfaces()` printed a
   warning and carried on, and the host got no IPv6 ruleset at all. Every IPv6 rule this package
   ships had never run anywhere.

   Behind it sat a second one that would have surfaced the moment the first was fixed: the IPv6
   network lookup searched `inet ` in the output of `ip -f inet6`, and on failing called
   `sys.exit()`, so a corrected device name would have aborted the whole program on any host with
   IPv6.

   `-json` has been in iproute2 since 4.15 and bookworm ships 6.1, so nothing is given up for it.
   What it buys is that neither of those bugs is expressible."""
   done = subprocess.run(args=[args.ip, '-json', *arguments], capture_output=True, encoding='UTF-8')
   if done.returncode != 0 or not done.stdout.strip():
      return []
   try:
      return json.loads(done.stdout)
   except json.JSONDecodeError:
      return []

def get_external_network(device, address, family):
   """The network of the address the route chose, which is not always the device's first.

   Matched on the address rather than taken from the top of the list, because an interface commonly
   carries several - a link-local beside a global, an alias, a second prefix - and the one that
   matters is the one traffic to the outside actually leaves from."""
   wanted = 'inet' if family == Family.IPV4 else 'inet6'
   for link in ip_json('addr', 'show', device):
      for info in link.get('addr_info', []):
         if info.get('family') != wanted: continue
         if info.get('scope') == 'link': continue
         if info.get('local') != address: continue
         return '{a}/{p}'.format(a=info['local'], p=info['prefixlen'])
   return None

def get_external_interface(destination, family):
   """Which device and address this host reaches the outside on, per family."""
   routes = ip_json('route', 'get', 'to', destination)
   if not routes: return None
   device, address = routes[0].get('dev'), routes[0].get('prefsrc')
   if device is None or address is None: return None
   network = get_external_network(device, address, family)
   if network is None: return None
   try:
      return Interface(address, network, device, family)
   except ValueError:
      return None

def get_external_ipv4_interface(destination):
   return get_external_interface(destination, Family.IPV4)

def get_external_ipv6_interface(destination):
   return get_external_interface(destination, Family.IPV6)

def get_parser():
   parser = argparse.ArgumentParser(description='Netfilter Persistence Plugin that configures a pure NetFilters Firewall for Linux')
   parser.add_argument('command', choices=['start', 'restart', 'reload', 'force-reload', 'stop', 'flush', 'save', 'test', 'add-service'], help='Manage netfilter rules for a firewall, or add a service it has no template for')
   parser.add_argument('service', nargs='?', help='add-service: the name of the service, lower-case letters and digits')
   parser.add_argument('--inbound', dest='direction', action='store_const', const='inbound', help='add-service: the host answers on these ports')
   parser.add_argument('--outbound', dest='direction', action='store_const', const='outbound', help='add-service: the host reaches out on these ports')
   parser.add_argument('--tcp', action='append', type=int, default=[], metavar='PORT', help='add-service: a TCP port this service uses - repeatable')
   parser.add_argument('--udp', action='append', type=int, default=[], metavar='PORT', help='add-service: a UDP port this service uses - repeatable')
   # NO DEFAULT, DELIBERATELY (ch2-5). A posture nobody chose is indistinguishable from an
   # accident, and this package has twice had rules rewritten by readers who found one.
   parser.add_argument('--posture', choices=['enforce', 'instrument', 'none'], help='add-service: what a limit does with excess - refuse it, count and admit it, or have no limit')
   parser.add_argument('--because', help='add-service: WHY that posture. Recorded beside the rule, and required')
   parser.add_argument('-nft', help='full path to nft - default /usr/sbin/nft', default='/usr/sbin/nft')
   parser.add_argument('-ip', help='full path to ip - default /usr/bin/ip', default='/usr/bin/ip')
   # WHY A DOCUMENTATION ADDRESS AND NOT A REAL ONE. This is only ever handed to `ip route get`,
   # which is a routing table lookup and sends no packet - so the usual objection to a public
   # resolver's address, that it leaks or that it depends on somebody else being up, does not
   # apply. What does apply is subtler: a host may carry a SPECIFIC route for a real service.
   # Split-tunnel VPNs commonly force DNS down the tunnel, and a policy route for 8.8.8.8 makes
   # discovery return the tunnel's device and address. The SPOOFING chain is then qualified by the
   # wrong interface and the spoof list subtracted against the wrong network, silently.
   #
   # 192.0.2.0/24 (RFC 5737, TEST-NET-1) and 2001:db8::/32 (RFC 3849) name no service, so nothing
   # routes them specially for a service's sake and the lookup follows the default route - which is
   # what discovery is actually asking about. A third party's address also has no business being a
   # default in a package other people install.
   #
   # The residual risk is a host that installs reject routes for bogon ranges; that is what these
   # two options are for.
   parser.add_argument('-ipv4dest', help='address used to find the external ipv4 device and source address, by routing table lookup - no packet is sent - default 192.0.2.1', default='192.0.2.1')
   parser.add_argument('-ipv6dest', help='address used to find the external ipv6 device and source address, by routing table lookup - no packet is sent - default 2001:db8::1', default='2001:db8::1')
   parser.add_argument('-b', '--basedir', help='path to the base configuration directory - default /etc/afirewall', default='/etc/afirewall')
   return parser

def parse_arguments():
   parser = get_parser()
   args = parser.parse_args()

   # AUTHORING IS NOT A PRIVILEGED OPERATION AND DOES NOT TOUCH THE KERNEL. It writes files into a
   # template tree, so it needs neither root, nor nft, nor ip, nor a route to the internet. The
   # checks below all exist for commands that load a ruleset; running them here would mean a person
   # could not add a service - or read `--help` - without root, which is how the discoverable
   # option becomes the undiscoverable one (ch2-4).
   if args.command == 'add-service':
      if args.direction is None: sys.exit('add-service needs --inbound or --outbound')
      if args.service is None: sys.exit('add-service needs a service name')
      if args.posture is None:
         sys.exit('add-service needs --posture. There is no default: a rule whose posture nobody '
                  'chose reads exactly like one somebody argued for, and this package has twice '
                  'had rules rewritten by readers who could not tell the difference.')
      if not args.because:
         sys.exit('add-service needs --because. The posture is recorded beside the rule so the '
                  'next reader inherits an argument rather than a habit.')
      return args

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
         li = re.sub(r'\s+', '', line)
         li = li.lower()
         if not li.startswith('#') and li.find(':') != -1:
            kv = li.split(':')
            config = branch(config, kv[0].split('.'), kv[1])
   return config

def users_a_service_matches(base_directory, service):
   """Which system users a service's rules match on, read out of the rules themselves.

   Read rather than declared, so nothing has to keep a second list of who needs whom in step
   with the templates. A service that matches no user - which is nearly all of them - yields
   nothing and is never in question."""
   users = set()
   for family in ('ipv4', 'ipv6'):
      for side in ('inbound', 'outbound'):
         path = '{base}/templates/{family}/{side}/{service}.rules'.format(
            base=base_directory, family=family, side=side, service=service)
         try:
            with open(path) as file:
               text = file.read()
         except OSError:
            continue
         # Brace-delimited expressions are dropped first. `meta skuid` names a user where it
         # is matched against one, and names the *key* of a set where it appears inside { } -
         # as in `add @s { meta skuid ct count over 500 }`, which otherwise reads 'ct' as a
         # user and disables the service for want of an account nobody meant to create. Set
         # bodies go the same way: `{ typeof meta skuid ... }` would otherwise yield 'size'.
         users.update(re.findall(r'meta skuid (\S+)', re.sub(r'\{[^{}]*\}', ' ', text)))
   return users

def disable_services_missing_their_users(base_directory, config):
   """Switch off any service whose skuid user does not exist on this host.

   `meta skuid nosuchuser` is not a rule that matches nothing. nft refuses to load the table
   that contains it, so one absent user costs the host every rule in that family - it ends up
   with no firewall rather than one service short. Enabling tor on a box without tor installed
   is an ordinary mistake and should not be able to do that.

   Switched off here rather than refused, because the alternative to a firewall missing one
   service is no firewall at all, and that is not the safer of the two."""
   for section in ('inbound', 'outbound'):
      for service, enabled in sorted(config.get(section, {}).items()):
         if not enabled:
            continue
         for user in sorted(users_a_service_matches(base_directory, service)):
            try:
               pwd.getpwnam(user)
            except KeyError:
               warn('{section}.{service} is enabled but the user it matches on ({user}) does '
                    'not exist here - disabling it, because the rule would otherwise take the '
                    'whole ruleset down with it'.format(section=section, service=service,
                                                        user=user))
               config[section][service] = False
               break
   return config

def get_interfaces():
   interfaces = []
   interface = get_external_ipv4_interface(args.ipv4dest)
   if interface != None:
      interfaces.append(interface)
   else:
      print('Warning: no IPv4 interface found. There was no valid route to ' + args.ipv4dest)
   interface = get_external_ipv6_interface(args.ipv6dest)
   if interface != None:
      interfaces.append(interface)
   else:
      print('Warning: no IPv6 interface found. There was no valid route to ' + args.ipv6dest)

   return interfaces

if __name__ == "__main__":
   args = parse_arguments()

   # The root check sits AFTER parsing and BEFORE anything that reaches the kernel, rather than at
   # the top of the file. It used to run first, which meant `--help` required root.
   if args.command == 'add-service':
      ports = [('tcp', port) for port in args.tcp] + [('udp', port) for port in args.udp]
      add_service(args.basedir, args.service, args.direction, ports, args.posture, args.because)
      sys.exit(0)

   if os.geteuid() != 0: sys.exit('Root permissions required.')

   config = disable_services_missing_their_users(args.basedir, get_configuration())
   interfaces = get_interfaces()

   match args.command:
      case 'start' | 'restart' | 'reload' | 'force-reload' | 'save':
         # Validate BEFORE tearing anything down. This ran the other way round, and `test`
         # exits on a bad ruleset - so the tables were already deleted by the time anything
         # checked, and a config that did not compile left the host with no firewall at all.
         # nft -c is happy to check a ruleset whose tables are currently loaded, so there is
         # nothing to be gained by flushing first.
         for interface in interfaces:
            nft_input = test(args.basedir, interface, config)
         stop()
         for file in glob.glob(args.basedir + '/ipv[46].nft'):
             print('Loading rules from ' + file)
             start(file)
      case 'stop' | 'flush':
         stop()
      case 'test':
         for interface in interfaces:
            test(args.basedir, interface, config)
