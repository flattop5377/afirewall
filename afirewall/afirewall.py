#!/usr/bin/python3
from enum import Enum
from ipaddress import ip_address, ip_network
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

import argparse
import glob
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

IPV4_ADDRESS_REGEX_PATTERN = r'.*src ([0-9\.]+) .*'
IPV4_DEVICE_REGEX_PATTERN = '.*dev ([0-9a-zA-Z]+) .*'
IPV6_ADDRESS_REGEX_PATTERN = '.*src ([0-9a-f:]+) .*'
IPV6_DEVICE_REGEX_PATTERN = '.*dev ([0-9a-f:]+) .*'

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

def get_external_interface_address_or_device(destination, regex):
   ip_route = subprocess.run(args=[args.ip, '-o', 'route', 'get', 'to', destination], capture_output=True, encoding='UTF-8')
   match = re.search(regex, ip_route.stdout)
   if match is None: return None
   return match.group(1)

def get_external_ipv4_network(device):
   try:
      ip_ad_show = subprocess.run(args=[args.ip, '-o', '-f', 'inet', 'ad', 'show', device], capture_output=True, encoding='UTF-8')
      match = re.search(r'.*inet ([0-9\./]+) .*', ip_ad_show.stdout)
      if match is None: sys.exit('Failed to find local IPV4 network in: ' + ip_ad_show.stdout)
      return match.group(1)
   except TypeError:
      return None

def get_external_ipv6_network(device):
   try:
      ip_ad_show = subprocess.run(args=[args.ip, '-o', '-f', 'inet6', 'ad', 'show', device], capture_output=True, encoding='UTF-8')
      match = re.search(r'.*inet ([0-9\./]+) .*', ip_ad_show.stdout)
      if match is None: sys.exit('Failed to find local IPV4 network in: ' + ip_ad_show.stdout)
      return match.group(1)
   except TypeError:
      return None

def get_external_ipv4_interface(destination):
   address = get_external_interface_address_or_device(destination, IPV4_ADDRESS_REGEX_PATTERN)
   device = get_external_interface_address_or_device(destination, IPV4_DEVICE_REGEX_PATTERN)
   network = get_external_ipv4_network(device)
   try:
     interface = Interface(address, network, device, Family.IPV4)
   except ValueError:
     interface = None
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

SERVICE_NAME = re.compile(r'^[a-z][a-z0-9]*$')

#: Where a family keeps its address type and its selector. The whole reason ipv6 went years
#: without loading is that these two got copied from the ipv4 template instead of chosen, so the
#: generator picks them from the family rather than from whatever it wrote last.
FAMILIES = {
   'ipv4': {'set_type': 'ipv4_addr', 'selector': 'ip'},
   'ipv6': {'set_type': 'ipv6_addr', 'selector': 'ip6'},
}

def wrap_comment(text, indent):
   """A paragraph as nft comment lines, at a width the rest of the package already uses.

   The argument is the reason this tool exists, and an argument nobody can read because it ran off
   the side of the file is not much better than one nobody wrote."""
   words, lines, current = text.split(), [], ''
   for word in words:
      if current and len(current) + 1 + len(word) > 92 - len(indent):
         lines.append(current)
         current = word
      else:
         current = current + ' ' + word if current else word
   if current: lines.append(current)
   return '\n'.join(indent + '# ' + line for line in lines)

def limit_rules(name, direction, family, ports, posture, indent):
   """The limit-bearing rules for one service, in whichever posture was argued for.

   THE VERDICT IS THE POSTURE. `continue` hands the packet to the accept below and instruments it;
   `over ... drop` refuses it. There is no third choice here and no default - `ch2-5` says refusing
   is the feature, because a posture nobody chose is exactly what this package spent two arguments
   recovering from."""
   if posture == 'none': return []
   selector = FAMILIES[family]['selector']
   key = 'saddr' if direction == 'inbound' else 'daddr'
   rules = []
   for protocol, port in ports:
      if posture == 'enforce':
         rate = '{s} {k} limit rate over 5/minute'.format(s=selector, k=key)
         count = '{s} {k} ct count over 20'.format(s=selector, k=key)
         verdict = 'drop'
      else:
         rate = '{s} {k} limit rate 5/minute'.format(s=selector, k=key)
         count = '{s} {k} ct count over 20'.format(s=selector, k=key)
         verdict = 'continue'
      rules.append('{i}ct state new {p} dport {n} update @{name}_rate_limit {{ {r} }} {v}'.format(
         i=indent, p=protocol, n=port, name=name, r=rate, v=verdict))
      rules.append('{i}ct state new {p} dport {n} add @{name}_connection_limit {{ {c} }} {v}'.format(
         i=indent, p=protocol, n=port, name=name, c=count, v=verdict))
   return rules

def render_service_template(name, direction, family, ports, posture, because):
   """One service's rules file, in the shape the package's own templates use.

   The spacing is the point. These are whitespace-sensitive by hand and nothing validates the
   layout, so a person adding a service either matches an existing file exactly or produces a
   ruleset that loads and reads badly - which is why `ch2-1` counts hand-authoring as a defect
   rather than a chore."""
   title = ('Outbound ' if direction == 'outbound' else '') + name.upper()
   set_type = FAMILIES[family]['set_type']
   out = ['  #############################################################################',
          '  #',
          '  ## {title} Rules'.format(title=title),
          '  #']
   # The argument goes NEXT TO THE RULE it defends, not in the file header - and in one place, not
   # both. A header copy would be a second home for the same sentence, and the one that drifts is
   # always the one further from the code. Where there is no limit there is no posture note, so
   # the header is the only place left for it.
   if posture == 'none':
      out += [wrap_comment(because, '  '), '  #']
   out += ['  #############################################################################', '']
   if posture != 'none':
      for kind, timeout in (('rate_limit', True), ('connection_limit', False)):
         out += ['  ##',
                 '  # {n} {k}'.format(n=name.upper(), k=kind.replace('_', ' ')),
                 '  #',
                 '  set {n}_{k} {{'.format(n=name, k=kind),
                 '    type {t}'.format(t=set_type),
                 '    size 65535']
         if timeout: out.append('    timeout 900s')
         out += ['    flags dynamic', '  }', '']
      out.append('')
   out.append('  chain ACCEPT_{N} {{'.format(N=name.upper()))
   if posture != 'none':
      out += ['    ##',
              wrap_comment('LIMIT POSTURE: {p} — {w}'.format(p=posture, w=because), '    '),
              '    #']
      out += limit_rules(name, direction, family, ports, posture, '    ')
   for protocol, port in ports:
      out.append('    ct state new,established {p} dport {n} accept'.format(p=protocol, n=port))
   out += ['  }', '']
   return '\n'.join(out)

def insert_after_last(text, pattern, addition, what):
   """Put a line where the block it belongs to ends, rather than at a marker nobody maintains.

   A generated `# ADD SERVICES HERE` comment would be a second thing to keep true, and the first
   person to tidy it would silently break this. The blocks are already distinguishable by what
   their lines DO."""
   matches = list(re.finditer(pattern, text, re.M))
   if not matches: sys.exit('Cannot find where to add ' + what + ' - base.rules has changed shape')
   at = matches[-1].end()
   return text[:at] + '\n' + addition + text[at:]

def add_service_to_base(base, name, direction, family, ports):
   """The four edits in base.rules a person adding a service by hand has to remember.

   THE FOURTH IS THE ONE THAT GETS FORGOTTEN. A service needs its include, its jump, its config
   key - and a reply path in the OPPOSITE table, because both directions default to drop and an
   inbound service whose replies are not admitted answers nobody. Forgetting it produces a service
   that looks configured and does not work, which is the failure this whole package is arranged
   to make loud."""
   opposite = 'outbound' if direction == 'inbound' else 'inbound'
   base = insert_after_last(
      base,
      r"^\{% if " + direction + r"\.\w+ %\}\{% include '" + family + r"/" + direction + r"/[^']+' %\}\{% endif %\}$",
      "{{% if {d}.{n} %}}{{% include '{f}/{d}/{n}.rules' %}}{{% endif %}}".format(
         d=direction, n=name, f=family),
      'the ' + direction + ' include')
   for protocol, port in ports:
      base = insert_after_last(
         base,
         r"^\{% if " + direction + r"\.\w+ %\}    \S+ dport \d+ jump ACCEPT_\w+\{% endif %\}$",
         "{{% if {d}.{n} %}}    {p} dport {t} jump ACCEPT_{N}{{% endif %}}".format(
            d=direction, n=name, p=protocol, t=port, N=name.upper()),
         'the ' + direction + ' jump')
      base = insert_after_last(
         base,
         r"^\{% if " + direction + r"\.\w+ %\}    \S+ sport \d+ ct state established accept\{% endif %\}$",
         "{{% if {d}.{n} %}}    {p} sport {t} ct state established accept{{% endif %}}".format(
            d=direction, n=name, p=protocol, t=port),
         "the reply path in the " + opposite + ' table')
   return base

def add_service(base_directory, name, direction, ports, posture, because):
   """`afirewall add-service`. Five files, and the person only says what the service is.

   Refuses rather than defaults, throughout. A name that already exists, a posture with no
   argument, a service with no ports - each is a question with an answer the person has and this
   tool does not."""
   if not SERVICE_NAME.match(name):
      sys.exit('A service name is lower-case letters and digits, starting with a letter: ' + name)
   if not ports:
      sys.exit('A service needs at least one --tcp or --udp port')
   for family in FAMILIES:
      path = '{b}/templates/{f}/{d}/{n}.rules'.format(b=base_directory, f=family, d=direction, n=name)
      if os.path.exists(path):
         sys.exit(path + ' already exists. Edit it, or pick another name - this will not overwrite '
                         'a template somebody may have argued for.')
   for family in FAMILIES:
      path = '{b}/templates/{f}/{d}/{n}.rules'.format(b=base_directory, f=family, d=direction, n=name)
      with open(path, 'w') as handle:
         handle.write(render_service_template(name, direction, family, ports, posture, because))
      base_path = '{b}/templates/{f}/base.rules'.format(b=base_directory, f=family)
      with open(base_path) as handle:
         base = handle.read()
      with open(base_path, 'w') as handle:
         handle.write(add_service_to_base(base, name, direction, family, ports))
      print('Wrote ' + path + ' and updated ' + base_path)
   conf_path = base_directory + '/afirewall.conf'
   with open(conf_path) as handle:
      conf = handle.read()
   if not conf.endswith('\n'): conf += '\n'
   with open(conf_path, 'w') as handle:
      handle.write(conf + '{d}.{n}: disable\n'.format(d=direction, n=name))
   print('Added {d}.{n} to {c}, disabled. Enable it when the service is there.'.format(
      d=direction, n=name, c=conf_path))

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
   parser.add_argument('-ipv4dest', help='destination used to find the external ipv4 address and device - default 8.8.8.8', default='8.8.8.8')
   parser.add_argument('-ipv6dest', help='destination used to find the external ipv6 address and device - default 2001:4860:4860:0:0:0:0:8888', default='2001:4860:4860:0:0:0:0:8888')
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
