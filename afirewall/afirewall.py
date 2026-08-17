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
import tomllib
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


#: EVERY TABLE THIS PACKAGE OWNS, and the list has to be complete or `stop` leaves one loaded.
#: The forward pair is conditional — a host that declares no forwarded service never has them — so
#: deleting them is allowed to fail and does, silently, which is why they can be named here
#: unconditionally rather than needing the configuration read to find out.
OWNED_TABLES = (('ip', 'a-firewall-inbound-ipv4'), ('ip', 'a-firewall-outbound-ipv4'),
                ('ip', 'a-firewall-forward-ipv4'), ('ip6', 'a-firewall-inbound-ipv6'),
                ('ip6', 'a-firewall-outbound-ipv6'), ('ip6', 'a-firewall-forward-ipv6'))

def stop(nft):
   for family, table in OWNED_TABLES:
      subprocess.run(args=[nft, 'delete', 'table', family, table],
                     capture_output=True, encoding='UTF-8')

def start(nft, nft_input):
   """Load a ruleset, and say so when it does not load.

   The return code used to go unread and stderr was captured and thrown away, so a load that
   failed printed 'Loading rules from ...' and exited 0 with the host unprotected. A firewall
   that cannot say whether it is running is worse than one that is plainly off."""
   nft_result = subprocess.run(args=[nft, '-f', nft_input], capture_output=True, encoding='UTF-8')
   if nft_result.returncode != 0:
      sys.exit('Failed to load ' + nft_input + ': ' + nft_result.stderr.strip())

def test(nft, template_directory, interface, config):
   nft_input = process_scripts(template_directory, interface, config)
   if nft_input != None:
      nft_result = subprocess.run(args=[nft, '-c', '-f',  nft_input], capture_output=True, encoding='UTF-8')
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

#: WHAT EACH COUNTER IS ACTUALLY COUNTING, in words rather than in a constant's name. The kernel
#: names are what the templates emit and what `nft` prints; nobody should have to translate
#: NUMBER_OF_PORT_ZERO_SEGMENTS_DROPPED in their head to read a diagnostic.
COUNTER_LABELS = (
   ('NUMBER_OF_SPOOFS_DROPPED', 'source could not have arrived here'),
   ('NUMBER_OF_NOT_LOCAL_DROPPED', 'not addressed to this host'),
   ('NUMBER_OF_INVALID_FLAGS_DROPPED', 'TCP flags RFC 9293 forbids'),
   ('NUMBER_OF_FRAGMENTS_DROPPED', 'non-first fragments'),
   ('NUMBER_OF_PORT_ZERO_SEGMENTS_DROPPED', 'port zero, either direction'),
)

def read_counters(nft):
   """(direction, family, name) -> {packets, bytes}, for the tables this package owns.

   Keyed on the table's direction as well as the name, because inbound and outbound both define
   NUMBER_OF_INVALID_FLAGS_DROPPED and only one of them ever moves. Summing them would report the
   outbound chain's zero as the inbound chain's silence.
   """
   done = subprocess.run(args=[nft, '-j', 'list', 'counters'], capture_output=True, encoding='UTF-8')
   if done.returncode != 0:
      sys.exit('could not read the counters from ' + nft + ': ' + done.stderr.strip())
   found = {}
   for obj in json.loads(done.stdout).get('nftables', []):
      counter = obj.get('counter')
      table = (counter or {}).get('table', '')
      if not table.startswith('a-firewall-'):
         continue
      # a-firewall-<direction>-<family>, and the name is built by the templates rather than parsed
      # from anywhere, so splitting it is reading this package's own convention back.
      _, _, direction, family = table.split('-')
      found[(direction, family, counter['name'])] = {'packets': counter['packets'],
                                                     'bytes': counter['bytes']}
   return found

def show_counters(nft, as_json):
   """Print what the sanity chains have actually stopped, both families side by side.

   SIDE BY SIDE BECAUSE THAT IS WHERE THE ASYMMETRIES ARE. Every defect this package found in its
   own sanity chains during August 2026 was one family differing from the other - ipv6 spoofing at
   the wrong priority, ipv6 with no fragment chain at all, ipv4's fragment chain behind defrag -
   and `nft list counters` prints the two families in separate blocks a screen apart, which is
   exactly the layout that hides it.

   A ZERO IS NOT A CLEAN BILL OF HEALTH and the footer says so, because that misreading is the one
   this package has actually made. It has three causes and this display cannot tell them apart:
   nothing of that kind arrived, the rule cannot be reached, or something upstream dropped it
   first. `tools/lab.py` is what distinguishes them, by sending the traffic on purpose.

   AND AN ABSENT COUNTER IS NOT A ZERO, in either output. The table prints `-`; the JSON simply has
   no record for it. Emitting a zero would claim the host looked and saw nothing, when what is true
   is that the rule is not there - which is how a release without an ipv6 fragment chain reads
   identically to one that has never seen a fragment.
   """
   found = read_counters(nft)
   if not found:
      sys.exit('no afirewall counters are loaded, so this host is not running a ruleset this '
               'package built. `afirewall reload` builds one; `nft list tables` says what is there.')

   if as_json:
      # ONE OBJECT WITH A LIST IN IT, not a bare array: a consumer that wants to iterate can, and
      # anything this needs to say later has somewhere to go without changing the shape it already
      # publishes. Each record carries its own label, so a reader is not required to hold a
      # translation table for the kernel's names.
      print(json.dumps({'counters': [
         {'direction': direction, 'family': family, 'name': name, 'label': label,
          'packets': found[(direction, family, name)]['packets'],
          'bytes': found[(direction, family, name)]['bytes']}
         for direction in ('inbound', 'outbound', 'forward')
         for family in ('ipv4', 'ipv6')
         for name, label in COUNTER_LABELS
         if (direction, family, name) in found]}))
      return

   for direction in ('inbound', 'outbound', 'forward'):
      rows = [(label, found.get((direction, 'ipv4', name)), found.get((direction, 'ipv6', name)))
              for name, label in COUNTER_LABELS]
      rows = [r for r in rows if r[1] is not None or r[2] is not None]
      if not rows:
         continue
      print('\n{d}{pad}{v4:>12}{v6:>12}'.format(d=direction, pad=' ' * (36 - len(direction)),
                                                v4='ipv4', v6='ipv6'))
      for label, four, six in rows:
         print('  {l:<34}{f:>12}{s:>12}'.format(
            l=label, f='-' if four is None else four['packets'],
            s='-' if six is None else six['packets']))

   print('\nA zero has three causes and this cannot tell them apart: nothing of that kind '
         'arrived,\nthe rule cannot be reached, or something upstream dropped it first. `-` means '
         'the counter\nis not loaded at all. tools/lab.py settles it by sending the traffic on '
         'purpose.')

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
               'outbound': config['outbound'],
               # THE SERVICES, ALREADY CHOSEN AND ALREADY RENDERED. base.rules loops over these
               # rather than naming each service in six places (ch8-3), so the include, the jump
               # and the reply in the other direction's chain all come from one record and cannot
               # disagree about a name or a port (ch8-4).
               'services': service_bodies(base_directory, interface.family.name.lower(), config)
            }).dump(output_name)
   except FileNotFoundError as e:
      sys.exit('Unable to write a pure NetFilters Firewall for Linux rules to ' + output_name + ' because: ' + e.message)
   except TemplateNotFound as e:
      sys.exit('Unable to find included template ' + e.message)

   return output_name

def ip_json(ip, *arguments):
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
   done = subprocess.run(args=[ip, '-json', *arguments], capture_output=True, encoding='UTF-8')
   if done.returncode != 0 or not done.stdout.strip():
      return []
   try:
      return json.loads(done.stdout)
   except json.JSONDecodeError:
      return []

def get_external_network(ip, device, address, family):
   """The network of the address the route chose, which is not always the device's first.

   Matched on the address rather than taken from the top of the list, because an interface commonly
   carries several - a link-local beside a global, an alias, a second prefix - and the one that
   matters is the one traffic to the outside actually leaves from."""
   wanted = 'inet' if family == Family.IPV4 else 'inet6'
   for link in ip_json(ip, 'addr', 'show', device):
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
   if not ip_json(ip, 'link', 'show', device):
      sys.exit('No such device on this host: ' + device + ' (named in ' + path + '). Nothing is '
               'generated - a stated interface that is not there is a typo, not a reason to guess.')
   return device

def get_external_interface_by_name(ip, device, family):
   """Build an Interface for a device the operator named, per family.

   A device with no address in a family gets no ruleset for it, which is the same answer discovery
   gives when there is no route - a host without IPv6 is not a host with a broken IPv6 firewall."""
   wanted = 'inet' if family == Family.IPV4 else 'inet6'
   for link in ip_json(ip, 'addr', 'show', device):
      for info in link.get('addr_info', []):
         if info.get('family') != wanted or info.get('scope') == 'link':
            continue
         try:
            return Interface(info['local'], '{a}/{p}'.format(a=info['local'], p=info['prefixlen']),
                             device, family)
         except ValueError:
            return None
   return None

def get_external_interface(ip, destination, family):
   """Which device and address this host reaches the outside on, per family."""
   routes = ip_json(ip, 'route', 'get', 'to', destination)
   if not routes: return None
   device, address = routes[0].get('dev'), routes[0].get('prefsrc')
   if device is None or address is None: return None
   network = get_external_network(ip, device, address, family)
   if network is None: return None
   try:
      return Interface(address, network, device, family)
   except ValueError:
      return None

def get_parser():
   # THIRTEEN SUBCOMMANDS AND A PERSON NEEDS THREE. The list is flat because argparse gives one
   # positional, and read cold it offers `restore`, `start`, `restart`, `reload`, `force-reload`,
   # `stop`, `flush` and `save` with equal weight - eight names netfilter-persistent sends and
   # nobody types. This package is a shim between ansible, a person, and nft; a front door that
   # cannot say which three verbs are for the person is the shim failing at its own job.
   #
   # An epilog rather than subparsers, because subparsers would change how netfilter-persistent's
   # own verbs are dispatched to buy a nicer --help, and this file is the plugin it runs.
   parser = argparse.ArgumentParser(
      description='Netfilter Persistence Plugin that configures a pure NetFilters Firewall for Linux',
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog="""\
the three you will actually type:

  afirewall enable inbound.smtp     open a service, and say whether that changed anything
  afirewall disable inbound.smtp    close it again
  afirewall reload                  rebuild the ruleset from the config and load it

  enable and disable only edit the configuration. NOTHING REACHES THE KERNEL UNTIL `reload`.

adding a service this package does not ship:

  afirewall add-service gemini --inbound --tcp 1965 \\
      --posture enforce --because "an anonymous peer that replaces itself"
  afirewall enable inbound.gemini
  afirewall reload

  --posture and --because are required and have no defaults: a rule whose posture nobody
  chose reads exactly like one somebody argued for.

from a configuration manager:

  enable/disable print one JSON object - {"changed": true, "flag": ..., "was": ..., "now": ...}
  and exit 0 whether or not anything changed. Gate the reload on `changed`, and pass
  --dry-run for a check run rather than letting the caller pretend.

everything else on that list is netfilter-persistent's vocabulary - restore, start, restart,
force-reload, stop, flush, save - and arrives from the system rather than from you.""")
   # TWO REAL ACTIONS, AND SEVEN NAMES FOR THEM, BECAUSE ONLY TWO OF THE NAMES ARE OURS.
   #
   # What this program does is `restore` a saved ruleset or `regenerate` one from the
   # configuration. Those are the words that say what happens, and they are the ones to reach for.
   #
   # `start`, `save` and `flush` are netfilter-persistent's, not ours: it runs the plugins in
   # /usr/share/netfilter-persistent/plugins.d with `run-parts -a <verb>`, and its own `reload` and
   # `restart` both call the plugin with `start` — so `start` is what arrives at boot AND what
   # `systemctl restart netfilter-persistent` produces, and there is no verb it can send that means
   # "rebuild". `start` therefore means restore, which reads oddly and is the contract rather than a
   # choice. Renaming it would simply stop the plugin working.
   #
   # `restart`, `reload` and `force-reload` are never sent by netfilter-persistent at all. They
   # exist here for a person or a configuration manager, so they are aliases of `regenerate`, which
   # is what somebody typing them after editing afirewall.conf means.
   parser.add_argument('command', choices=['restore', 'regenerate', 'start', 'restart', 'reload', 'force-reload', 'stop', 'flush', 'save', 'test', 'add-service', 'enable', 'disable', 'counters'], help='restore a saved ruleset, or regenerate one from the configuration. start/restart/reload/force-reload are netfilter-persistent\'s names for those two. enable/disable set one flag in afirewall.conf and report what changed; counters shows what the sanity chains have stopped')
   parser.add_argument('service', nargs='?', help='add-service: the name of the service, lower-case letters and digits. enable/disable: the flag to set, as <inbound|outbound>.<service>')
   # A DRY RUN IS THE COMMAND'S JOB AND NOT THE CALLER'S (ch3-3). ansible's --check does not run a
   # `command:` at all: it returns rc 0 with empty stdout and a register that is DEFINED, so a play
   # reading back what it just did reads a fabricated success and asserts on it. The pair that
   # makes a check run real is `check_mode: false` on the task with this flag passed explicitly.
   parser.add_argument('--dry-run', action='store_true', help='enable/disable: do everything except the write, validation included, and report what would have changed')
   parser.add_argument('--json', action='store_true', help='counters: one JSON object instead of the table, for something that consumes the numbers')
   parser.add_argument('--inbound', dest='direction', action='store_const', const='inbound', help='add-service: the host answers on these ports')
   parser.add_argument('--outbound', dest='direction', action='store_const', const='outbound', help='add-service: the host reaches out on these ports')
   parser.add_argument('--forward', dest='direction', action='store_const', const='forward', help='add-service: the host forwards these ports to somewhere else - needs --to')
   parser.add_argument('--to', help='add-service: where a forwarded service actually runs, as an address this host can route to')
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

   # ONE PLACE, BEFORE ANYTHING BRANCHES. This lived inside the add-service checks first, which
   # meant `enable --json` was accepted and silently did nothing - a flag that reads as a request
   # and is not one. enable and disable print JSON unconditionally, because ch3-6 says a
   # configuration manager must not have to ask for it.
   if args.json and args.command != 'counters':
      sys.exit('--json is counters\' flag. enable and disable print one JSON object always, and '
               'nothing else here has numbers to publish.')

   # AUTHORING IS NOT A PRIVILEGED OPERATION AND DOES NOT TOUCH THE KERNEL. It writes files into a
   # template tree, so it needs neither root, nor nft, nor ip, nor a route to the internet. The
   # checks below all exist for commands that load a ruleset; running them here would mean a person
   # could not add a service - or read `--help` - without root, which is how the discoverable
   # option becomes the undiscoverable one (ch2-4).
   if args.command == 'add-service':
      if args.direction is None: sys.exit('add-service needs --inbound, --outbound or --forward')
      if args.direction == 'forward' and not args.to:
         sys.exit('--forward needs --to: a forwarded service is a record with somewhere to send '
                  'the traffic, and the rules that admit it are derived from that address (ch4-8).')
      if args.to and args.direction != 'forward':
         sys.exit('--to only means anything with --forward. An inbound or outbound service '
                  'terminates on this host, so there is nowhere else to send it.')
      if args.service is None: sys.exit('add-service needs a service name')
      if args.posture is None:
         sys.exit('add-service needs --posture. There is no default: a rule whose posture nobody '
                  'chose reads exactly like one somebody argued for, and this package has twice '
                  'had rules rewritten by readers who could not tell the difference.')
      if not args.because:
         sys.exit('add-service needs --because. The posture is recorded beside the rule so the '
                  'next reader inherits an argument rather than a habit.')
      return args

   # SETTING A FLAG IS NOT A PRIVILEGED OPERATION EITHER, and it stops short of the kernel for the
   # same reason add-service does: it edits one line of a text file. Requiring nft, ip and a route
   # to the internet before it would mean a configuration manager could not set a flag on a host
   # whose network is the thing being fixed - and `--help` would need all three to print.
   #
   # It does need the configuration, so those two checks are made here rather than skipped.
   if args.command in ('enable', 'disable'):
      if args.service is None:
         sys.exit(args.command + ' needs a flag, as <inbound|outbound>.<service>')
      if not os.access(args.basedir, mode=os.R_OK):
         sys.exit('Base configuration directory ' + args.basedir + ' can\'t be opened')
      if not os.access(args.basedir + '/afirewall.conf', mode=os.R_OK):
         sys.exit('Configuration file ' + args.basedir + '/afirewall.conf can\'t be opened')
      return args

   if not shutil.which(args.nft, mode=os.X_OK): sys.exit(args.nft + ' is not executable')
   nft_completed = subprocess.run(args=[args.nft, '-V'], capture_output=True, encoding='UTF-8')
   pattern = re.compile('nftables')
   if not pattern.match(nft_completed.stdout): sys.exit(args.nft + ' doesn\'t appear to be nft?')

   if not shutil.which(args.ip, mode=os.X_OK): sys.exit(args.ip + ' is not executable')
   ip_completed = subprocess.run(args=[args.ip, '-V'], capture_output=True, encoding='UTF-8')
   pattern = re.compile('ip utility.*')
   if not pattern.match(ip_completed.stdout): sys.exit(args.ip + ' doesn\'t appear to be ip?')

   # COUNTERS ASKS THE KERNEL AND READS NO CONFIGURATION, so it stops here. It needs nft to be
   # real - checked above - and needs nothing under the base directory, and requiring one would
   # mean a host whose /etc/afirewall is gone could not be asked what its firewall has stopped,
   # which is exactly when somebody wants to know.
   if args.command == 'counters':
      return args

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

def get_configuration(base_directory):
   config = {}
   with open(base_directory + '/afirewall.conf', 'r') as file:
      for line in file:
         li = re.sub(r'\s+', '', line)
         li = li.lower()
         if not li.startswith('#') and li.find(':') != -1:
            kv = li.split(':')
            config = branch(config, kv[0].split('.'), kv[1])
   return config

#: A SERVICE NAME IS THE FLAG, THE CHAIN AND THE FILENAME AT ONCE, so what it may contain is
#: decided by the strictest of the three. `inbound.<name>` is split on '.' by get_configuration, the
#: chain is ACCEPT_<NAME> in nft, and the file is <name>.rules - so a dot, a hyphen or a space each
#: break something different and none of them break it loudly.
SERVICE_NAME = re.compile(r'^[a-z0-9]+$')

#: The canonical shape, which is the package's existing one rather than a style this path invents
#: (ch2-6). A generated template that looked generated would split the package into two dialects,
#: and ch2-7 is the claim that there is only one.
#: The spacing is surveyed rather than invented: of the seventeen outbound templates, every one
#: without limits puts `chain` on the line after the header rule and ends with a trailing blank
#: line, and the two that carry sets leave two blank lines before the chain. That is why the
#: blank lines belong to {sets} rather than to this string - an unlimited service has none.
SERVICE_TEMPLATE = """\
  #############################################################################
  #
  ## {title}
  #
{description}  #############################################################################
{sets}  chain ACCEPT_{upper} {{
{posture}{rules}  }}

"""

#: THE SET LABELS ARE NORMALISED, and the hand-written ones were not. They read `SSH connection
#: rate limit`, `POSTGRES rate limit`, `TCP 2914 connection rate limit` and `Baculs Storage Daemon
#: connection rate limit` - four shapes and a typo, describing the same thing. One shape off the
#: service's own name loses nothing and is listed in ch8-8 as an expected difference.
LIMIT_SETS = """
  ##
  # {label} rate limit
  #
  set {service}_rate_limit {{
    type {addr}
    size 65535
    timeout 900s
    flags dynamic
  }}

  ##
  # {label} connection limit
  #
  set {service}_connection_limit {{
    type {addr}
    size 65535
    flags dynamic
  }}


"""

CATALOGUE = 'services.toml'

def load_catalogue(base_directory):
   """Every service record, shipped first and the base directory's merged OVER them (ch8-9).

   MERGED RATHER THAN REPLACED, and the distinction is the whole of ch8-9. A base directory that
   replaced the catalogue would rebuild ch2-U4 one file along: a stranger adding one service would
   adopt the whole list and stop receiving every upstream addition and correction to it. Merging by
   (direction, name) means a local record overrides exactly the service it names and nothing else.

   Keyed on the pair rather than the name, because `inbound.wireguard` and `outbound.wireguard` are
   different services that happen to share a word.
   """
   records = {}
   for root in (SHIPPED, base_directory):
      path = root + '/' + CATALOGUE
      if not os.path.exists(path):
         continue
      with open(path, 'rb') as file:
         for record in tomllib.load(file).get('service', []):
            records[(record['direction'], record['name'])] = record
   return records

def service_bodies(base_directory, family, config):
   """direction -> the enabled services in that direction, each with the text of its rules.

   THE HAND-WRITTEN TEMPLATE WINS (ch8-7). A file for this service is used instead of rendering its
   record, which is how the two `meta skuid` services keep a shape no record can say - and how an
   operator overrides a shipped service without the catalogue having to anticipate them. ch8-U3 is
   the part that is not decided: a template left lying around silently freezes that service.

   ENABLED SERVICES ONLY, so base.rules carries no per-service guard at all. That is what removes
   the class of fault this chapter was written for: a guard cannot name a flag that does not exist
   if there is no guard.
   """
   bodies = {'inbound': [], 'outbound': [], 'forward': []}
   for (direction, name), record in sorted(load_catalogue(base_directory).items()):
      if not config.get(direction, {}).get(name):
         continue
      relative = family + '/' + direction + '/' + name + '.rules'
      handwritten = first_existing(base_directory + '/templates/' + relative,
                                   SHIPPED + '/templates/' + relative)
      # A FORWARDED SERVICE TERMINATES SOMEWHERE ELSE, and that is the only difference the
      # vocabulary carries (ch4-8). Its two rules are the crossing: one admitting traffic TO the
      # destination and one admitting the answer back FROM it - measured on 2026-08-17 as the
      # minimum that lets a namespaced service be reached while a `policy drop` forward chain
      # refuses the rest. No blanket `ct state established,related accept` anywhere near it, for
      # the reason ch1-1 refuses one on input: the return path is admitted by this service's own
      # record or not at all.
      if direction == 'forward':
         if not record.get('to'):
            sys.exit('forward.' + name + ' declares no `to`, so there is nowhere to forward it. A '
                     'forwarded service is a record with somewhere to send the traffic (ch4-8).')
         # A DESTINATION BELONGS TO ONE FAMILY, and putting an IPv4 address in an ip6 table is a
         # parse error that costs the whole family - the same failure mode as `ip saddr` in an ip6
         # template, which is how this package's v6 ruleset once spent years not loading. A record
         # may carry `to_ipv4` and `to_ipv6`; a plain `to` serves whichever family it belongs to,
         # and the other simply has no crossing. That is a statement rather than an omission: a
         # service reachable only over v4 SHOULD have no v6 rules.
         where = record.get('to_' + family, record.get('to'))
         wanted = 4 if family == 'ipv4' else 6
         if ip_address(where).version != wanted:
            continue
         address = 'ip daddr' if family == 'ipv4' else 'ip6 daddr'
         source = 'ip saddr' if family == 'ipv4' else 'ip6 saddr'
         crossing = []
         for protocol, port in record_ports(record, family):
            crossing.append(address + ' ' + where + ' ' + protocol + ' dport ' + str(port)
                            + ' ct state new,established accept')
            crossing.append(source + ' ' + where + ' ' + protocol + ' sport ' + str(port)
                            + ' ct state established accept')
         bodies[direction].append({'name': name, 'upper': name.upper(), 'to': where,
                                   'jumps': [], 'replies': [], 'crossing': crossing,
                                   'include': None, 'body': None})
         continue

      # HOW THE TRAFFIC IS SELECTED, and there are two answers. Almost every service is chosen by
      # a port; outbound tor and btc are chosen by the owner of the local socket, which no port
      # can express. Both produce a jump and a reply from the SAME record, which is the whole of
      # ch8-4 — whichever way a service is selected, its two directions are written once.
      if record.get('selector'):
         matches = [record['selector']]
      else:
         matches = [protocol + ' dport ' + str(port)
                    for protocol, port in record_ports(record, family)]
      jumps = [match + ' jump ACCEPT_' + name.upper() for match in matches]

      # THE REPLY IS DERIVED UNLESS THE RECORD SAYS OTHERWISE, and exactly one record says
      # otherwise. Everywhere else a service's answer is a conntrack reply on what it selected on,
      # which is why deriving it is safe. DHCP is answered from an address the request never
      # named, so its reply arrives NEW or INVALID and a rule asking for ESTABLISHED never fires —
      # it needs a real accept, and its record carries that rule verbatim rather than being bent
      # into the general shape.
      replies = record.get('reply_' + family, record.get('reply'))
      if replies is None:
         replies = [(record['selector'] if record.get('selector')
                     else protocol + ' sport ' + str(port)) + ' ct state established accept'
                    for protocol, port in (record_ports(record, family)
                                           if not record.get('selector') else [(None, None)])]

      bodies[direction].append({
         'name': name,
         'upper': name.upper(),
         'jumps': jumps,
         'replies': replies,
         'include': relative if os.path.exists(handwritten) else None,
         'body': None if os.path.exists(handwritten) else render_service(family, record),
      })
   return bodies

def record_ports(record, family):
   """This family's protocol/port pairs, which are not always the other family's.

   `outbound.dhcp` is udp/67 on ipv4 and udp/547 on ipv6, because DHCPv6 is a different protocol on
   a different port. Flattening that to one list would have silently broken v6 DHCP - the migration
   only found it because it refused to proceed when two families disagreed by anything it did not
   understand. A record may override its ports per family, and exactly one does.
   """
   pairs = record.get('ports_' + family, record['ports'])
   return [(pair.split('/')[0], int(pair.split('/')[1])) for pair in pairs]

def render_service(family, record):
   """One service's rules, for one family, in the shape the package's own templates use.

   BOTH FAMILIES ALWAYS (ch2-6). What differs between them is two tokens - the set's address type
   and the saddr selector - and getting the second wrong is not a rule that matches nothing but a
   parse error, which is how this package's ipv6 ruleset spent years not loading.

   ONE RENDERER, TWO CALLERS. The catalogue renders through this and so does `add-service`, so a
   service somebody adds cannot come out in a different shape from one that shipped. That is ch2-7
   held by construction rather than by a test comparing two code paths.
   """
   addr = 'ipv4_addr' if family == 'ipv4' else 'ipv6_addr'
   saddr = 'ip saddr' if family == 'ipv4' else 'ip6 saddr'
   service = record['name']
   title = record.get('title') or (service.upper() + ' Rules')
   posture = record.get('posture')
   ports = record_ports(record, family)
   limited = posture in ('enforce', 'instrument')

   description = ''
   if record.get('description'):
      # `{family}` is the ONE substitution a record's prose may make, and it exists because
      # wireguard's note points at its own family's counterpart. Anything richer would make the
      # catalogue a second template language, which is what this chapter is removing.
      for line in record['description'].format(family=family).rstrip('\n').split('\n'):
         description += ('  #' + line).rstrip() + '\n'
      # The banner closes with a bare `#` before its rule, which is the shape every hand-written
      # header with prose already has.
      description += '  #\n'

   # The unlimited shape is ntp.rules': header, one blank line, chain. The limited one is
   # postgres.rules': the set declarations between them, and two blank lines before the chain.
   sets = (LIMIT_SETS.format(label=service.upper(), service=service, addr=addr)
           if limited else '')

   note = ''
   if limited:
      # THE ARGUMENT IS THE OPERATOR'S AND THE NUMBERS ARE NOT. `because` is why this posture
      # rather than the other one, which is the question only a person can answer (ch2-4). The
      # rate and count are values this package inherited by copying one template to make the next,
      # and ch8-U1 is the first time they have been visible in one table to be argued about.
      argument = record.get('because', '').rstrip('\n').split('\n')
      note = '    ##\n    # LIMIT POSTURE: ' + posture + ' — ' + argument[0] + '\n'
      for line in argument[1:]:
         note += ('    # ' + line).rstrip() + '\n'
      note += '    #\n'

   rules = ''
   verdict = 'drop' if posture == 'enforce' else 'continue'
   over = 'over ' if posture == 'enforce' else ''
   for protocol, port in ports:
      if limited:
         rules += ('    ct state new ' + protocol + ' dport ' + str(port) + ' update @' + service
                   + '_rate_limit { ' + saddr + ' limit rate ' + over + record['rate'] + ' } '
                   + verdict + '\n')
         rules += ('    ct state new ' + protocol + ' dport ' + str(port) + ' add @' + service
                   + '_connection_limit { ' + saddr + ' ct count over ' + str(record['count'])
                   + ' } ' + verdict + '\n')
      rules += ('    ct state new,established ' + protocol + ' dport ' + str(port) + ' accept\n')

   return SERVICE_TEMPLATE.format(title=title, description=description, sets=sets,
                                  upper=service.upper(), posture=note, rules=rules)

def add_service(base_directory, service, direction, ports, posture, because, to=None):
   """Add a service by adding a record. That is the whole of it (ch8-3).

   THIS FUNCTION USED TO WRITE FIVE THINGS: a template in each family, an include, a jump, and the
   reply in the other direction's chain - and the reply was the one easiest to forget, which is
   why three shipped services were missing one. Now it appends one record and everything else is
   derived, so the fault it used to be possible to make is not expressible.

   Written to the BASE DIRECTORY's catalogue, never to the shipped one. That is what ch8-9's merge
   buys: a stranger's service sits in their own file and the package's list keeps arriving with
   upgrades, instead of the two being the same file and the upgrade being a conflict.
   """
   if not SERVICE_NAME.match(service or ''):
      sys.exit('A service name is lower-case letters and digits only: it becomes a config flag '
               'split on ".", an nft chain called ACCEPT_' + str(service).upper() + ', and a '
               'record key. "' + str(service) + '" breaks at least one of the three.')
   if not ports:
      sys.exit('add-service needs at least one --tcp or --udp port. A service with no ports is a '
               'flag that renders an empty chain nothing can reach.')
   if (direction, service) in load_catalogue(base_directory):
      sys.exit(direction + '.' + service + ' is already in the catalogue. Edit its record - it is '
               'an ordinary record (ch2-7) - or pick another name.')

   record = ['[[service]]',
             'name = "' + service + '"',
             'direction = "' + direction + '"',
             'title = "' + service.upper() + ' Rules"',
             'ports = [' + ', '.join('"' + p + '/' + str(n) + '"' for p, n in ports) + ']']
   if to:
      record.append('to = "' + to + '"')
   record.append('posture = "' + posture + '"')
   if posture in ('enforce', 'instrument'):
      # The rate and count this package has always used for a service nobody has measured. They
      # are ch8-U1's subject and the catalogue is where that is now visible.
      record += ['rate = "' + ('50/minute' if posture == 'enforce' else '5/minute') + '"',
                 'count = ' + ('200' if posture == 'enforce' else '20'),
                 'because = """\n' + because.replace('\\', '\\\\') + '\n"""']

   catalogue = base_directory + '/' + CATALOGUE
   existing = ''
   if os.path.exists(catalogue):
      existing = open(catalogue).read().rstrip('\n') + '\n\n'
   with open(catalogue, 'w') as file:
      file.write(existing + '\n'.join(record) + '\n')

   set_flag(base_directory, direction + '.' + service, 'disable', False)

   # DISABLED ON ARRIVAL, and that is the whole handover. Declaring a service says what its rule
   # would be; switching it on is a separate decision, and it is the one ch3's subcommand makes
   # honestly.
   # NOT `warn`: nothing is wrong, and a success that prints the word Warning teaches a reader to
   # discount the word everywhere else in this program.
   print(direction + '.' + service + ' is declared in ' + catalogue + ' and switched off. Turn it '
         'on with `afirewall enable ' + direction + '.' + service + '`, then `afirewall reload`.',
         file=sys.stderr)

#: THE SET A FLAG HAS TO BE IN, read off the template tree and never off afirewall.conf.
#:
#: The conf is the thing being validated, so a validator that trusted it would bless `inbound.tor`
#: forever - which is precisely the fault ch3-2 exists to refuse. A flag is real when some family
#: has a template to include for it; that is the same rule the package's own skew tests apply from
#: both directions, and it means the answer follows the templates a release actually ships.
#:
#: Both roots, in the same precedence as everything else here: an admin who dropped a template
#: under the base directory has a real flag for it, whether or not the package has ever heard of
#: the service (ch2-8).
def known_flags(base_directory):
   # BOTH HOMES A SERVICE CAN HAVE, because ch8-7 leaves two. A record is the ordinary answer and
   # a hand-written template is the exception, and a flag is real if either exists - so this reads
   # the catalogue and the template tree and takes the union. Reading only the catalogue would
   # refuse `outbound.tor`, which is a real service with a real template and deliberately no
   # record.
   flags = {direction + '.' + name for direction, name in load_catalogue(base_directory)}
   for root in (base_directory, SHIPPED):
      for family in ('ipv4', 'ipv6'):
         for side in ('inbound', 'outbound'):
            directory = os.path.join(root, 'templates', family, side)
            if not os.path.isdir(directory):
               continue
            for name in os.listdir(directory):
               if name.endswith('.rules'):
                  flags.add(side + '.' + name[:-len('.rules')])
   return flags

def set_flag(base_directory, flag, value, dry_run):
   """Set one flag, and report what actually happened as one JSON object (ch3-5, ch3-6).

   THE FILE IS EDITED LINE BY LINE RATHER THAN REWRITTEN. afirewall.conf is a dpkg conffile
   carrying comments that argue for its own contents, and a function that parsed it into a dict and
   printed the dict back would silently discard every one of them. So the matching line is replaced
   where it sits and a new flag is appended, which is also what keeps `lineinfile` and this
   subcommand interchangeable on the same file (ch1-2).

   `was` IS null WHEN THE FLAG WAS NOT THERE, and that is not the same as `disable`. Both leave the
   service off, and only one of them means somebody decided: reporting the absent case as `disable`
   would invent a decision nobody took, in the output a configuration manager reads.
   """
   flag = flag.lower()
   if flag not in known_flags(base_directory):
      sys.exit('Nothing declares ' + flag + ' — no record in ' + CATALOGUE + ' and no template — '
               'so setting it would write a line that survives every reload and governs nothing. '
               'That is what `inbound.tor` was. Declare it with `afirewall add-service`, or check '
               'the spelling.')

   path = base_directory + '/afirewall.conf'
   with open(path) as file:
      lines = file.readlines()

   was = None
   for number, line in enumerate(lines):
      bare = re.sub(r'\s+', '', line).lower()
      if bare.startswith('#') or ':' not in bare:
         continue
      if bare.split(':')[0] == flag:
         was = bare.split(':')[1] or None
         lines[number] = flag + ': ' + value + '\n'
         break
   else:
      # Appended rather than inserted in any particular place: the file is an unordered list of
      # flags, and a tool that sorted it would rewrite lines nobody asked it to touch.
      lines.append(flag + ': ' + value + '\n')

   changed = was != value
   # WRITTEN ONLY WHEN SOMETHING CHANGES, which is not merely an optimisation. Rewriting a file
   # with identical content still moves its mtime, and something else on the host is entitled to
   # watch that - so a no-op that touched the file would be a no-op only as far as this program's
   # own report was concerned.
   if changed and not dry_run:
      with open(path, 'w') as file:
         file.writelines(lines)

   # FLUSHED, so a person reading a terminal gets the answer before the advice about it. stdout
   # is block-buffered into a pipe and stderr is not, so without this the nudge below overtakes
   # the object it is about.
   print(json.dumps({'changed': changed, 'flag': flag, 'was': was, 'now': value}), flush=True)

   # THE HALF-DONE STATE THIS COMMAND LEAVES, SAID OUT LOUD. `enable` edits the configuration and
   # touches no kernel, so somebody who runs it and walks away has changed nothing that filters a
   # packet - and the JSON says `changed: true`, which is true about the file and easy to read as
   # true about the firewall. On stderr so it cannot corrupt the object a configuration manager
   # parses, and only when something changed, so a converged run stays quiet (ch3-7).
   #
   # NOT WHEN A FLAG ARRIVES ALREADY OFF. `add-service` writes its new flag as `disable`, which
   # changes the file and opens nothing, so telling that person to reload would be advice to do
   # nothing - and advice to do nothing is how the useful warnings stop being read.
   if changed and not dry_run and (value == 'enable' or was == 'enable'):
      warn(flag + ' is ' + value + 'd in the configuration and the kernel has not been told. '
           'Run `afirewall reload` to apply it.')

   # ch4-9, SAID AT THE MOMENT SOMEBODY CROSSES IT. Until a forwarded service is enabled this host
   # has no chain at the forward hook and forwards everything; the first one brings a chain into
   # existence at `policy drop` and everything else this machine was passing through - a container
   # runtime's published ports above all - stops. There is no posture that avoids that and is still
   # a firewall, so what the package owes is that nobody arrives there by surprise.
   if changed and value == 'enable' and flag.startswith('forward.'):
      already = [d + '.' + n for (d, n) in load_catalogue(base_directory)
                 if d == 'forward' and d + '.' + n != flag]
      config = get_configuration()
      if not any(config.get('forward', {}).get(other.split('.', 1)[1]) for other in already):
         warn('THIS IS THE FIRST FORWARDED SERVICE ON THIS HOST. Until now nothing filtered '
              'traffic this machine forwards; after the next reload a chain exists at the forward '
              'hook with policy drop, and everything else being forwarded - a container runtime\'s '
              'published ports, a tunnel, a namespace nobody declared - is refused. Declare those '
              'too, or do not enable this one (ch4-9).')

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

def get_interfaces(base_directory, ip, ipv4dest, ipv6dest):
   """Which interfaces the rules are generated against.

   STATED FIRST, DISCOVERED OTHERWISE. Trust is a policy statement about a network and the routing
   table is not a trust database: the default route says where packets go, not which network is
   hostile. Those agree on a single-NIC host and stop agreeing the moment a full-tunnel VPN moves
   the default route onto an overlay - where a private source address is entirely legitimate, so
   the anti-spoofing rules would be applied to the one interface they must not be."""
   stated = get_stated_external_device(base_directory)
   interfaces = []
   for family, destination in ((Family.IPV4, ipv4dest), (Family.IPV6, ipv6dest)):
      if stated is not None:
         interface = get_external_interface_by_name(ip, stated, family)
         absent = stated + ' has no ' + family.name + ' address'
      else:
         interface = get_external_interface(ip, destination, family)
         absent = 'there was no valid route to ' + destination
      if interface is not None:
         interfaces.append(interface)
      else:
         warn('no ' + family.name + ' interface found: ' + absent)
   return interfaces

def main():
   """The entry point, and it exists for a reason that outlived the one it was written for.

   THIS FILE HAD NO CALLABLE ENTRY POINT AT ALL - it ended in `if __name__ == "__main__":` with
   eighty-nine lines under it. The Python deliverable wanted one for `[project.scripts]`, and that
   deliverable was retired on 2026-08-17; what did not retire is that `plumb.toml` could name no
   production entry point either, so grounding never ran and every behavioural subject in this
   repository read `passed-wiring-not-verified`. Grounding is what catches orphaned code, and a
   package that cannot be entered cannot be asked.

   NOTHING BELOW REACHES BACK FOR WHAT THIS PARSED. `stop`, `start`, `test`, `ip_json`,
   `get_configuration` and interface discovery all read the parsed namespace off the module until
   2026-08-17, so extracting this body needed `global args` to keep them working - and a global is
   what made the extraction awkward rather than what the extraction needed. They take what they use
   now, which is the convention the rest of this file already had: `process_scripts`,
   `load_catalogue` and `set_flag` were all handed `base_directory` while `get_configuration`
   reached for it.

   What it cost while it lasted: the discovery tests had to FABRICATE the global -
   `afirewall.args = SimpleNamespace(ip=...)` - to ask a question about routing, and `main` being
   callable made the module state leak between calls rather than being set once per process.
   """
   args = parse_arguments()

   # The root check sits AFTER parsing and BEFORE anything that reaches the kernel, rather than at
   # the top of the file. It used to run first, which meant `--help` required root.
   if args.command == 'add-service':
      ports = [('tcp', port) for port in args.tcp] + [('udp', port) for port in args.udp]
      add_service(args.basedir, args.service, args.direction, ports, args.posture, args.because,
                  args.to)
      sys.exit(0)

   # EXIT ZERO WHETHER OR NOT ANYTHING CHANGED (ch3-5). Changed is reported in the output, never in
   # the status: a status that meant `changed` would break `afirewall enable x && ...` for every
   # person at a shell, to save a configuration manager one parse.
   if args.command in ('enable', 'disable'):
      set_flag(args.basedir, args.service,
               'enable' if args.command == 'enable' else 'disable', args.dry_run)
      sys.exit(0)

   # READS THE KERNEL, SO IT NEEDS ROOT, and it is placed with the commands that do rather than
   # with enable/disable which only edit a file. It changes nothing, which is why it sits before
   # everything that does.
   if args.command == 'counters':
      if os.geteuid() != 0: sys.exit('Reading the counters needs root: they live in the kernel.')
      show_counters(args.nft, args.json)
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
      config = disable_services_missing_their_users(args.basedir,
                                                    get_configuration(args.basedir))
      interfaces = get_interfaces(args.basedir, args.ip, args.ipv4dest, args.ipv6dest)
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
         test(args.nft, args.basedir, interface, config)

   def load():
      saved = sorted(glob.glob(GENERATED + '/ipv[46].nft'))
      if not saved:
         sys.exit('There is no saved ruleset in ' + GENERATED + ', so there is nothing to restore '
                  'and this host has no firewall. Nothing has been changed. Run `afirewall '
                  'regenerate` to build one from ' + args.basedir + '/afirewall.conf - it needs '
                  'the network to be up, because the external interface is found by routing '
                  'lookup unless it is named in ' + args.basedir + '/' + INTERFACES_FILE + '.')
      # NO `stop()` HERE ANY MORE, AND THE RULESET IS WHY. Each generated file now opens by
      # creating and deleting every table this package owns in its family, so loading it replaces
      # what was there in ONE nft transaction rather than in a teardown followed by a rebuild.
      #
      # What that removes is a window. `stop()` deleted the tables and then something had to load
      # the new ones, and between those two the host had no firewall at all - briefly on a good
      # run, and permanently on a bad one, because a load that failed after the teardown left
      # nothing behind. Now a file that fails to load leaves the previous ruleset in place, which
      # is the same posture `generate` already takes when it refuses rather than disarms.
      for file in saved:
         print('Loading rules from ' + file)
         start(args.nft, file)

   match args.command:
      # RESTORE, AND ONLY RESTORE. `start` is netfilter-persistent's name for this and arrives at
      # boot, when there is no network to discover an interface on - so restoring a saved ruleset
      # is the only thing that can work here, and rebuilding is what left hosts bare.
      #
      # IT DOES NOT QUIETLY GENERATE WHEN THERE IS NOTHING SAVED, and that restraint is the point.
      # A verb that usually restores and occasionally rebuilds is one whose behaviour depends on
      # state the caller cannot see, which is the shape of the bug this whole change exists to fix.
      # Nothing saved is a real fault - the package was installed and never configured - so it says
      # so and exits non-zero rather than doing the other thing. Packaging is where that gap is
      # closed: postinst regenerates once, and every boot after it restores.
      case 'restore' | 'start':
         load()
      # REGENERATE. The configuration has changed, or might have. This is also what corrects a
      # saved ruleset naming an address the host no longer has, which is the cost of persisting.
      case 'regenerate' | 'restart' | 'reload' | 'force-reload':
         generate()
         load()
      # SAVE WRITES THE RULESET DOWN AND DOES NOT LOAD IT, which is what the verb means to
      # netfilter-persistent. It used to be a synonym for restart, so asking to record the current
      # state also tore the firewall down and put it back.
      case 'save':
         generate()
      case 'stop' | 'flush':
         stop(args.nft)
      case 'test':
         generate()


if __name__ == "__main__":
   main()
