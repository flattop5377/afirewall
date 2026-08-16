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

#: Where the package's own copies live. THE ADMIN'S COPY WINS, and that ordering is the whole
#: arrangement: templates and lists are the package's, revised as it learns things, so they ship
#: here and are replaced on upgrade without asking. A file of the same name under the base
#: directory takes precedence, so somebody who needs a different ssh.rules still gets one - what
#: they no longer get is their copy silently deciding what happens on every future upgrade.
#:
#: They used to install only under /etc, which made all 73 of them dpkg conffiles. An upgrade then
#: kept an edited one and left an OLD TEMPLATE BESIDE A NEW base.rules - precisely the three-way
#: skew this package's own tests forbid, on the one machine where no test is running, producing a
#: table nft refuses and costing the host a whole address family.
SHIPPED = '/usr/share/afirewall'

#: Where the rendered ruleset goes. See process_scripts for why it is not the base directory.
GENERATED = '/var/lib/afirewall'

def first_existing(*paths):
   """The first of these that is there, or the last as the thing to complain about."""
   for path in paths:
      if os.path.exists(path):
         return path
   return paths[-1]

def get_spoofed_networks(base_directory, interface):
   name = '/lists/spoofed_' + interface.family.name + '_networks.list'
   filename = first_existing(base_directory + name, SHIPPED + name)
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
      loader = FileSystemLoader([base_directory + '/templates', SHIPPED + '/templates'])
   )

   template_name = "{family}/base.rules".format(family=interface.family.name.lower());
   # GENERATED, SO IT IS NEITHER CONFIGURATION NOR DATA. This is derived from the config and
   # rebuilt whenever the configuration is applied. Under /etc it was unowned by dpkg and churned
   # beneath anything watching configuration for change.
   #
   # IT WAS /run UNTIL 2026-08-16, WHICH MEANT THE HOST BOOTED WITH NO FIREWALL. The note that
   # chose it argued that emptying on boot makes loading a ruleset stale against the configuration
   # impossible - reasoning about the ruleset without reasoning about the boot, because the boot is
   # exactly when the rebuild it forces cannot work. netfilter-persistent runs this plugin before
   # the network is configured, so `ip route get` finds no route, no interface is discovered, and
   # nothing is generated. Measured on a host, 2026-08-16: `Warning: no IPV4 interface found`,
   # `Result=success`, and not one table in the kernel.
   #
   # PERSISTENCE IS THE POINT OF THE THING THIS IS A PLUGIN FOR. netfilter-persistent restores a
   # saved ruleset at boot; that is its whole job, and every other plugin it runs works that way.
   # Generating is what happens when the configuration CHANGES, not every time the machine starts.
   # So the rules persist and `start` restores them, while `reload` regenerates.
   #
   # Staleness is still real - these rules name the interface's address, so a host that boots on a
   # new one restores rules describing the old. It is handled by regenerating after the network is
   # up rather than by throwing the ruleset away, because a stale firewall is a smaller problem
   # than no firewall, and only one of the two announces itself.
   os.makedirs(GENERATED, exist_ok=True)
   output_name = GENERATED + "/" + interface.family.name.lower() + ".nft"

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

#: Where the operator states which interface faces a network they do not trust. A FILE IN THE BASE
#: DIRECTORY, and that is decided by how it has to persist: it must load and unload with the rules,
#: so it has to be an input to generation. A command-line flag does not survive netfilter-persistent
#: invoking this at boot with no arguments, and a unit drop-in or an environment file would be a
#: second persistence mechanism beside the one this package already has.
#:
#: Not a key in afirewall.conf, and the reason is the consumer rather than the format: that file is
#: composed by appending service flags, and a configuration manager restores one baseline shared by
#: every host before each run. A per-host fact there is erased by that restore every converge.
INTERFACES_FILE = 'interfaces.conf'

def get_stated_external_device(base_directory):
   """The interface the operator named, or None if they named none.

   Silence means discover, which is what keeps a single-NIC host working with no configuration at
   all - and that host is what this package was written for."""
   path = base_directory + '/' + INTERFACES_FILE
   if not os.path.exists(path):
      return None
   stated = []
   with open(path) as file:
      for line in file:
         li = line.split('#')[0].strip()
         if not li:
            continue
         # A CLOSED VOCABULARY, ON PURPOSE, AND ONE THAT GROWS BY ADDING ROLES. The format is
         # `<role>: <device>`, so the day a namespace needs an interface named as something other
         # than external - the host end of a veth, say - that is a new role rather than a new file
         # shape. Refusing an unknown one now is what makes adding one a visible decision instead
         # of something that quietly started working.
         if not li.startswith('external:'):
            sys.exit(path + ': `' + li.split(':')[0].strip() + '` is not a role this version knows. '
                     'The only one is `external`. The format is `<role>: <device>` so more can be '
                     'added, but a role that is not recognised is refused rather than ignored.')
         device = li.split(':', 1)[1].strip()
         if device:
            stated.append(device)
   if not stated:
      return None
   if len(stated) > 1:
      sys.exit(path + ' names more than one external interface ' + str(stated) + '. Only one is '
               'supported: the rules are generated against a single external device, and silently '
               'using the first would be worse than refusing.')
   device = stated[0]
   # REFUSED RATHER THAN FALLEN BACK FROM. A fallback to discovery would turn a typo into a firewall
   # that protects a different interface than the one it was told to - quiet, plausible, and exactly
   # the failure that inferring the interface at all was criticised for.
   if not ip_json('link', 'show', device):
      sys.exit('No such device on this host: ' + device + ' (named in ' + path + '). Nothing is '
               'generated - a stated interface that is not there is a typo, not a reason to guess.')
   return device

def get_external_interface_by_name(device, family):
   """Build an Interface for a device the operator named, per family.

   A device with no address in a family gets no ruleset for it, which is the same answer discovery
   gives when there is no route - a host without IPv6 is not a host with a broken IPv6 firewall."""
   wanted = 'inet' if family == Family.IPV4 else 'inet6'
   for link in ip_json('addr', 'show', device):
      for info in link.get('addr_info', []):
         if info.get('family') != wanted or info.get('scope') == 'link':
            continue
         try:
            return Interface(info['local'], '{a}/{p}'.format(a=info['local'], p=info['prefixlen']),
                             device, family)
         except ValueError:
            return None
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
   parser.add_argument('-b', '--basedir', help='path to the configuration directory, which overrides what the package ships in /usr/share/afirewall - default /etc/afirewall', default='/etc/afirewall')
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

def get_interfaces(base_directory):
   """Which interfaces the rules are generated against.

   STATED FIRST, DISCOVERED OTHERWISE. Trust is a policy statement about a network and the routing
   table is not a trust database: the default route says where packets go, not which network is
   hostile. Those agree on a single-NIC host and stop agreeing the moment a full-tunnel VPN moves
   the default route onto an overlay - where a private source address is entirely legitimate, so
   the anti-spoofing rules would be applied to the one interface they must not be."""
   stated = get_stated_external_device(base_directory)
   interfaces = []
   for family, destination in ((Family.IPV4, args.ipv4dest), (Family.IPV6, args.ipv6dest)):
      if stated is not None:
         interface = get_external_interface_by_name(stated, family)
         absent = stated + ' has no ' + family.name + ' address'
      else:
         interface = get_external_interface(destination, family)
         absent = 'there was no valid route to ' + destination
      if interface is not None:
         interfaces.append(interface)
      else:
         warn('no ' + family.name + ' interface found: ' + absent)
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

   def generate():
      """Build the rulesets from the configuration, and refuse rather than disarm.

      AN EMPTY INTERFACE LIST USED TO BE AN OUTCOME, AND IT WAS THE WORST ONE AVAILABLE. The loop
      below generated nothing, `stop()` then deleted whatever the kernel was holding, the glob
      found no files to load, and the program exited 0. A host that had a firewall a moment ago had
      none, and every instrument said the run succeeded.

      A family with no interface is still fine and still only a warning - a host without IPv6 is
      not a host with a broken IPv6 firewall. No interface in ANY family is a different statement:
      it means nothing could be built, and the only safe thing to do with a ruleset you cannot
      replace is leave it alone."""
      config = disable_services_missing_their_users(args.basedir, get_configuration())
      interfaces = get_interfaces(args.basedir)
      if not interfaces:
         sys.exit('No external interface was found in any family, so no ruleset can be built. '
                  'Nothing has been changed - whatever this host is running is still running. '
                  'If this is a boot, the network was not up yet and `start` should be restoring '
                  'the saved ruleset rather than rebuilding it; if it is not, name the interface '
                  'in ' + args.basedir + '/' + INTERFACES_FILE + '.')
      # Validate BEFORE tearing anything down. This ran the other way round, and `test`
      # exits on a bad ruleset - so the tables were already deleted by the time anything
      # checked, and a config that did not compile left the host with no firewall at all.
      # nft -c is happy to check a ruleset whose tables are currently loaded, so there is
      # nothing to be gained by flushing first.
      for interface in interfaces:
         test(args.basedir, interface, config)

   def load():
      saved = sorted(glob.glob(GENERATED + '/ipv[46].nft'))
      if not saved:
         sys.exit('There is no saved ruleset in ' + GENERATED + ' and none was generated, so '
                  'there is nothing to load. Run `afirewall reload` once the network is up.')
      stop()
      for file in saved:
         print('Loading rules from ' + file)
         start(file)

   match args.command:
      # RESTORE, DO NOT REBUILD. This is the verb netfilter-persistent calls at boot, and at boot
      # there is no network to discover an interface on. Restoring a saved ruleset is what this
      # plugin exists to do; rebuilding it here is what left hosts bare. A host with no saved
      # ruleset - a first install - still has to build one, and by then the network is up because
      # a person is running the command.
      case 'start':
         if not glob.glob(GENERATED + '/ipv[46].nft'):
            generate()
         load()
      # THE CONFIGURATION HAS CHANGED, OR MIGHT HAVE. Everything that is not a boot rebuilds, which
      # is also what corrects a saved ruleset that names an address the host no longer has.
      case 'restart' | 'reload' | 'force-reload':
         generate()
         load()
      # SAVE WRITES THE RULESET DOWN AND DOES NOT LOAD IT, which is what the verb means to
      # netfilter-persistent. It used to be a synonym for restart, so asking to record the current
      # state also tore the firewall down and put it back.
      case 'save':
         generate()
      case 'stop' | 'flush':
         stop()
      case 'test':
         generate()
