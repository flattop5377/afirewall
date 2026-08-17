from afirewall import afirewall
from jinja2 import Environment, FileSystemLoader
import os
import pwd
import re
import shutil
import subprocess
import tempfile
import unittest

#: Per family, because a spoof list is addresses and an ip6 table will not take an ipv4 one.
#: Short stand-ins for the real lists under lists/, which are what production reads.
SPOOFED = {
    'ipv4': ['10.0.0.0/8', '192.168.0.0/16'],
    'ipv6': ['fc00::/7', '2001:db8::/32'],
}

FAMILIES = ('ipv4', 'ipv6')

def services():
    """Every service the shipped config knows, so these tests follow the config rather
    than a second list of names that has to be remembered alongside it."""
    found = {'inbound': set(), 'outbound': set()}
    for line in open('afirewall.conf'):
        line = line.strip()
        if line and not line.startswith('#') and ':' in line:
            key = line.split(':', 1)[0].strip().lower()
            if '.' in key:
                section, name = key.split('.', 1)
                if section in found:
                    found[section].add(name)
    return found

def nft_binary():
    """Where nft actually is. PATH alone is not enough: nft lives in /usr/sbin, which is not
    on a non-root PATH, so looking only there skips this check on exactly the hosts that
    could run it. afirewall itself defaults to /usr/sbin/nft for the same reason."""
    found = shutil.which('nft')
    if found:
        return found
    for candidate in ('/usr/sbin/nft', '/sbin/nft'):
        if os.access(candidate, os.X_OK):
            return candidate
    return None

def render(family, device='eth0', spoofed=None, inbound=(), outbound=()):
    """Render base.rules the way afirewall does. `inbound`/`outbound` name what to switch
    on; anything unnamed is off, which is what an absent key already renders as."""
    env = Environment(loader=FileSystemLoader('templates'))
    config = {'inbound': {name: True for name in inbound},
              'outbound': {name: True for name in outbound}}
    # THE REAL FUNCTION, not a stand-in. base.rules loops over what this returns (ch8-3), so a
    # test rendering with a hand-built list would be testing a second implementation of the thing
    # under test — which is how chapter 2's drills came to pass against a NameError.
    return env.get_template(family + '/base.rules').render(
        EXTERNAL_DEVICE=device,
        EXTERNAL_ADDRESS='203.0.113.7',
        LOCAL_NETWORK='203.0.113.0/24',
        SPOOFED_NETWORKS=SPOOFED[family] if spoofed is None else spoofed,
        services=afirewall.service_bodies('.', family, config),
        **config)

def render_everything(family):
    enabled = services()
    return render(family, inbound=enabled['inbound'], outbound=enabled['outbound'])

class TestAfirewall(unittest.TestCase):
    def testConfigFileReadable(self):
        parser = afirewall.get_parser()
        args = parser.parse_args(['test', '-b=.'])
        self.assertTrue(os.access(args.basedir + '/afirewall.conf', mode=os.R_OK))

    def testSpoofDropsOnlyApplyToTheExternalDevice(self):
        """A private source address is spoofed off the internet and ordinary over a tunnel.
        Unqualified, these rules drop every packet wg0 carries - the overlay is a 192.168
        network and this chain runs at priority raw, ahead of every accept rule there is."""
        for family, selector in (('ipv4', 'ip saddr'), ('ipv6', 'ip6 saddr')):
            for network in SPOOFED[family]:
                self.assertIn('iifname eth0 {sel} {net}'.format(sel=selector, net=network),
                              render(family),
                              family + ' drops ' + network + ' without naming the device it arrived on')

    def testSpoofDropsNameTheDetectedDeviceNotAHardcodedOne(self):
        """EXTERNAL_DEVICE comes from the route to the internet, so it differs per host."""
        self.assertIn('iifname ens3 ip saddr 10.0.0.0/8', render('ipv4', device='ens3'))

    def testIpv6UsesTheIpv6Selector(self):
        """`ip saddr` does not parse inside an ip6 table. It went unnoticed for as long as
        it did because the loop that emits it never ran: ipv6 had no list to read."""
        rendered = render('ipv6')
        self.assertNotIn(' ip saddr ', rendered)

    def testIpv6CarriesNoIpv4Selectors(self):
        """An ip6 table rejects `ip saddr`, `ip protocol` and `ipv4_addr` outright, so a
        single one of them anywhere fails the whole ruleset rather than one rule."""
        rendered = render('ipv6', spoofed=['fc00::/7'])
        for selector in ('ipv4_addr', '{ ip saddr', '{ ip daddr', 'ip protocol icmp'):
            self.assertNotIn(selector, rendered, 'ipv6 still carries the ipv4 selector ' + selector)

    def testIpv6AcceptsNeighbourDiscoveryAndPacketTooBig(self):
        """ICMPv6 is load-bearing where ICMPv4 is advisory. Neighbour discovery is how IPv6
        resolves addresses at all, and packet-too-big is its only path-MTU signal because
        routers never fragment. Filtering either does not harden the host, it strands it."""
        rendered = render('ipv6')
        for kind in ('nd-neighbor-solicit', 'nd-neighbor-advert',
                     'nd-router-solicit', 'nd-router-advert', 'packet-too-big'):
            self.assertIn('icmpv6 type ' + kind + ' accept', rendered,
                          'ipv6 does not accept ' + kind)

    def testIpv6DropsIcmpv4OnlyTypes(self):
        """These have no ICMPv6 equivalent; naming them is a parse error, not a dead rule."""
        rendered = render('ipv6')
        for kind in ('source-quench', 'timestamp-request', 'timestamp-reply',
                     'info-request', 'info-reply', 'address-mask-request', 'address-mask-reply'):
            self.assertNotIn(kind, rendered, 'ipv6 still names the ICMPv4 type ' + kind)

    def testBothFamiliesReachTheirIcmpChain(self):
        """The inbound table jumped VALID_ICMP while the chain was only ever defined in the
        outbound one, and the outbound table never jumped at all - so outbound ICMPv6 died on
        the drop policy. Each table has to both define the chain and reach it."""
        for family, jump in (('ipv4', 'ip protocol icmp jump VALID_ICMP'),
                             ('ipv6', 'meta l4proto ipv6-icmp jump VALID_ICMP')):
            rendered = render(family)
            self.assertEqual(2, rendered.count('chain VALID_ICMP'),
                             family + ' does not define VALID_ICMP in both tables')
            self.assertEqual(2, rendered.count(jump),
                             family + ' does not jump to VALID_ICMP from both tables')

    def testTheUsersAServiceNeedsAreReadFromItsRules(self):
        """Read out of the templates rather than declared beside them, so there is no second
        list of who needs whom to fall out of step. Most services match no user at all."""
        self.assertEqual({'debian-tor'}, afirewall.users_a_service_matches('.', 'tor'))
        self.assertEqual({'btc'}, afirewall.users_a_service_matches('.', 'btc'))
        self.assertEqual(set(), afirewall.users_a_service_matches('.', 'ssh'))
        self.assertEqual(set(), afirewall.users_a_service_matches('.', 'wireguard'))

    def testNoEnabledServiceIsLeftMatchingAUserThatIsNotThere(self):
        """The invariant, asserted rather than a fixed expectation, because whether debian-tor
        exists is a property of whichever machine is running the suite.

        `meta skuid nosuchuser` does not match nothing - nft refuses the table holding it, so
        one absent user costs every rule in that family and the host ends up with no firewall
        instead of one service fewer."""
        every = services()
        config = {'inbound': {name: True for name in every['inbound']},
                  'outbound': {name: True for name in every['outbound']}}
        guarded = afirewall.disable_services_missing_their_users('.', config)
        for section in ('inbound', 'outbound'):
            for service, enabled in guarded[section].items():
                if not enabled:
                    continue
                for user in afirewall.users_a_service_matches('.', service):
                    try:
                        pwd.getpwnam(user)
                    except KeyError:
                        self.fail(section + '.' + service + ' left enabled, but ' + user +
                                  ' does not exist - nft would refuse the whole table')

    def testAServiceThatMatchesNoUserIsNeverDisabled(self):
        """The guard has to be surgical. Switching off ssh because tor's user is absent would
        be a worse outage than the one it is preventing."""
        guarded = afirewall.disable_services_missing_their_users(
            '.', {'inbound': {'ssh': True, 'http': True}, 'outbound': {'ssh': True}})
        self.assertTrue(guarded['inbound']['ssh'])
        self.assertTrue(guarded['inbound']['http'])
        self.assertTrue(guarded['outbound']['ssh'])

    def testBothFamiliesHaveASpoofListAndItIsRead(self):
        """ipv6 spent its whole life returning an empty list here, so the chain it feeds
        rendered with no rows and reported nothing about being empty."""
        from afirewall.afirewall import Interface, get_spoofed_networks
        for family, address, network in (
                (1, '203.0.113.7', '203.0.113.0/24'),
                (2, '2a01:4f8:c17:2b::7', '2a01:4f8:c17:2b::/64')):
            found = get_spoofed_networks('.', Interface(address, network, 'eth0', family))
            self.assertTrue(found, 'family ' + str(family) + ' read no spoofed networks')

    def testIpv6SpoofListOmitsWhatNeighbourDiscoveryNeeds(self):
        """Both are marked not-globally-reachable by IANA and both are ordinary sources on
        the external device: fe80::/10 carries neighbour discovery and router advertisement,
        and ::/128 is the required source for duplicate address detection. Dropping either
        does not harden the host, it strands it. The IPv4 list can drop its own link-local
        because ARP is layer 2 and carries no IP source at all."""
        listed = [line.strip() for line in open('lists/spoofed_IPV6_networks.list')
                  if line.strip() and not line.strip().startswith('#')]
        self.assertNotIn('fe80::/10', listed)
        self.assertNotIn('::/128', listed)
        self.assertIn('fc00::/7', listed)
        self.assertIn('ff00::/8', listed)

    # ---- the rendered ruleset, rather than the template that produced it -------------
    #
    # A template is Jinja and nft never sees it; nft sees what it renders to. These pin the
    # rendered shape so a template cannot drift into something that still renders but no
    # longer produces a ruleset nft will take, or take cleanly.

    def testNothingUnrenderedSurvivesIntoTheRuleset(self):
        """A stray marker means a condition was written wrong. nft reports it as a syntax
        error somewhere in a 900-line file rather than as the template mistake it is."""
        for family in FAMILIES:
            rendered = render_everything(family)
            for marker in ('{%', '%}', '{{', '}}'):
                self.assertNotIn(marker, rendered, family + ' left ' + marker + ' in the output')

    def testEveryJumpHasAChainToLandOn(self):
        """The failure this catches is a service wired to another service's chain. It renders
        fine, and nft then rejects the whole table - so the host ends up with no firewall at
        all rather than one rule too few."""
        for family in FAMILIES:
            rendered = render_everything(family)
            defined = set(re.findall(r'^\s*chain (\w+)', rendered, re.M))
            for target in sorted(set(re.findall(r'jump (\w+)', rendered))):
                self.assertIn(target, defined,
                              family + ' jumps to ' + target + ', which no chain defines')

    def testEveryServiceBodyResolves(self):
        """Every enabled service produces either rules or a template that is there.

        base.rules includes a PATH FROM A VARIABLE since chapter 8, so a missing file is no longer
        something a reader can spot by grepping for `{% include %}` — it is a TemplateNotFound
        while a firewall is being brought up. This asks the resolver instead of the text."""
        for family in FAMILIES:
            every = services()
            bodies = afirewall.service_bodies(
                '.', family, {'inbound': {n: True for n in every['inbound']},
                              'outbound': {n: True for n in every['outbound']}})
            for direction in ('inbound', 'outbound'):
                for service in bodies[direction]:
                    with self.subTest(service=direction + '/' + service['name'], family=family):
                        if service['include']:
                            self.assertTrue(os.path.isfile('templates/' + service['include']),
                                            service['include'] + ' is named and is not there')
                        else:
                            self.assertIn('chain ACCEPT_' + service['upper'], service['body'],
                                          service['name'] + ' rendered no chain')

    def testEveryStaticIncludeResolvesToAFileThatExists(self):
        """An include naming a file that is not there costs nothing until the key guarding it
        is switched on - and then raises TemplateNotFound at the moment somebody is trying to
        bring a firewall up. base.rules carried three of them (orport, dirport, bitcoin, the
        last a near-miss for btc.rules), each unreachable only because no config key set it.

        SINCE CHAPTER 8 THERE ARE NONE, and their absence is the claim rather than a side effect:
        `base.rules` names no service at all now (ch8-3), so a per-service include is a line that
        should not have come back. Any literal include that does appear is still checked, because
        the next one somebody adds will be the one that is wrong.
        """
        for family in FAMILIES:
            source = open('templates/' + family + '/base.rules').read()
            included = re.findall(r"\{% include '([^']+)' %\}", source)
            self.assertEqual([], [p for p in included if '/inbound/' in p or '/outbound/' in p],
                             family + '/base.rules names a service include again; services are '
                             'reached through their records now (ch8-3)')
            for path in included:
                self.assertTrue(os.path.isfile('templates/' + path),
                                family + '/base.rules includes ' + path + ', which is not there')
                self.assertTrue(path.startswith(family + '/'),
                                family + '/base.rules includes ' + path + ' from another family')

    def testEveryConfigKeyHasADeclarationBehindIt(self):
        """A key nothing declares is a switch wired to nothing. Turn it on and nothing happens,
        which reads as a firewall rule that is in force and is not. `inbound.tor` was one for
        years, and `inbound.bitcoin` was a near-miss for the btc that does exist.

        ASKED OF THE CATALOGUE SINCE CHAPTER 8, and it is now the ONLY skew left in this area:
        three files had to agree before, and two do now (ch8-U2)."""
        catalogue = afirewall.load_catalogue('.')
        declared = services()
        for side in ('inbound', 'outbound'):
            for service in sorted(declared[side]):
                self.assertIn((side, service), catalogue,
                              side + '.' + service + ' is in afirewall.conf and nothing declares '
                              'it — no record in services.toml and no template')

    def testEveryDeclarationHasAConfigKeyToTurnItOn(self):
        """The same skew from the other side. A record no key names cannot be switched on, so it
        is work that looks like coverage and provides none."""
        declared = services()
        for (side, service) in sorted(afirewall.load_catalogue('.')):
            self.assertIn(service, declared[side],
                          side + '.' + service + ' is declared and has no key in afirewall.conf')

    def testEveryHandWrittenTemplateIsClaimedByARecord(self):
        """The escape hatch's own skew (ch8-7). A template is reached only through the record that
        names its service, so one lying beside the catalogue with no record is a file the renderer
        will never open — coverage that provides none, which is what this test always asked.

        It is a much smaller question than it used to be: two templates rather than sixty-six."""
        catalogue = afirewall.load_catalogue('.')
        for family in FAMILIES:
            for side in ('inbound', 'outbound'):
                directory = 'templates/{f}/{s}'.format(f=family, s=side)
                if not os.path.isdir(directory):
                    continue
                for name in sorted(os.listdir(directory)):
                    if not name.endswith('.rules'):
                        continue
                    service = name[:-len('.rules')]
                    self.assertIn((side, service), catalogue,
                                  directory + '/' + name + ' has no record, so nothing reaches it')

    def testOutboundLimitsCarryTheirOwnVerdict(self):
        """A limit rule ending in `continue` counts and refuses nothing. When the match fails
        evaluation moves to the next rule, and the next rule accepts unconditionally - so the
        limit is only ever a counter. `over ... drop` is what actually turns traffic away."""
        for family in FAMILIES:
            for service in ('tor', 'btc'):
                path = 'templates/{f}/outbound/{s}.rules'.format(f=family, s=service)
                source = open(path).read()
                self.assertIn('ct count over', source, path + ' bounds no concurrency')
                self.assertIn('limit rate over', source, path + ' bounds no rate')
                for line in source.splitlines():
                    if 'ct count over' in line or 'limit rate over' in line:
                        self.assertTrue(line.rstrip().endswith('drop'),
                                        path + ': limit without a verdict -> ' + line.strip())

    def testEveryServiceJumpsIntoItsOwnChain(self):
        """A jump to some *other* service's chain, which the jump-target check above cannot
        see because that chain does exist. btc jumped into ACCEPT_TOR in both directions and
        both families: skuid btc never matches skuid debian-tor, so bitcoind fell through to
        the drop policy and ACCEPT_BTC was never reached. Enabled together they rendered,
        loaded, and silently firewalled bitcoind off in both directions.

        Read from the guard rather than the port, because the guard is what the operator
        switched on and the chain is what they expect it to reach."""
        wired = re.compile(r'\{% if (?:inbound|outbound)\.([a-z0-9]+) %\}.*?jump (ACCEPT_\w+)')
        for family in FAMILIES:
            source = open('templates/' + family + '/base.rules').read()
            for service, chain in wired.findall(source):
                self.assertEqual('ACCEPT_' + service.upper(), chain,
                                 family + ': ' + service + ' jumps into ' + chain)

    def testIndentationStaysEvenAndTabFree(self):
        """nft does not care, but a mix of tabs and spaces is how a template stops being
        diffable against the ruleset nft prints back."""
        for family in FAMILIES:
            for number, line in enumerate(render_everything(family).splitlines(), start=1):
                if not line.strip():
                    continue
                self.assertNotIn('\t', line, family + ':' + str(number) + ' indents with a tab')
                indent = len(line) - len(line.lstrip(' '))
                self.assertEqual(0, indent % 2,
                                 family + ':' + str(number) + ' indents by ' + str(indent))

    def testBracesBalance(self):
        """An unclosed chain swallows every rule after it into itself."""
        for family in FAMILIES:
            rendered = render_everything(family)
            self.assertEqual(rendered.count('{'), rendered.count('}'),
                             family + ' opens and closes a different number of braces')

    def testWireguardIsWiredOnWhicheverSideIsSwitchedOn(self):
        """The three-part change afirewall.conf documents: include the chain, jump to it,
        and accept the replies from the other table. Miss one and the tunnel is half open,
        which for a tunnel is the same as shut."""
        for family in FAMILIES:
            for side in ('inbound', 'outbound'):
                rendered = render(family, **{side: ('wireguard',)})
                self.assertIn('chain ACCEPT_WIREGUARD', rendered, family + '/' + side)
                self.assertIn('udp dport 51820 jump ACCEPT_WIREGUARD', rendered, family + '/' + side)
                self.assertIn('udp sport 51820 ct state established accept', rendered,
                              family + '/' + side + ' never accepts the replies')

    def testWireguardOffLeavesNoTraceOfItself(self):
        """A disabled service contributes a blank line and nothing else."""
        for family in FAMILIES:
            rendered = render(family)
            self.assertNotIn('51820', rendered)
            self.assertNotIn('ACCEPT_WIREGUARD', rendered)

    @unittest.skipUnless(nft_binary() and os.geteuid() == 0,
                         'nft -c needs root and an installed nftables')
    def testNftAcceptsTheRenderedRuleset(self):
        """The only check here that is not a guess about what nft wants: everything above
        asserts what the output should look like, this one asks nft.

        Root, because `nft -c` parses first and only then reads the kernel's ruleset to
        validate against - and that second half is CAP_NET_ADMIN. Unprivileged it gets far
        enough to report a syntax error and no further, which makes a clean run there mean
        nothing. afirewall itself refuses to run as non-root for the same reason. `-c`
        changes nothing either way."""
        for family in FAMILIES:
            # tor and btc match on skuid, and those users exist only on hosts running them.
            enabled = services()
            for side in ('inbound', 'outbound'):
                enabled[side] -= {'tor', 'btc'}
            rendered = render(family, inbound=enabled['inbound'], outbound=enabled['outbound'])
            with tempfile.NamedTemporaryFile('w', suffix='.nft') as handle:
                handle.write(rendered)
                handle.flush()
                checked = subprocess.run([nft_binary(), '-c', '-f', handle.name],
                                         capture_output=True, encoding='UTF-8')
            self.assertEqual(0, checked.returncode, family + ': ' + checked.stderr)

if __name__ == '__main__':
    unittest.main()

class TestInterfaceDiscovery(unittest.TestCase):
    """Which device and address the firewall thinks it is protecting.

    THIS IS A REGRESSION TEST FOR A BUG THAT COST EVERY HOST ITS IPv6 FIREWALL. Discovery used to
    regex `ip`'s human-readable output, and the IPv6 device pattern was `[0-9a-f:]+` - the pattern
    for an IPv6 address, applied to a field holding a device NAME. It matches no normal interface,
    so IPv6 discovery returned nothing, get_interfaces() warned and continued, and the generated
    ruleset was IPv4-only. Nothing failed; the firewall was simply half there.

    These use fixtures rather than the machine's own network, so the case that was broken - a host
    with global IPv6 on a normally-named interface - is testable on a workstation that has none.
    """

    def discover(self, family, destination, fixtures):
        # THIS USED TO FABRICATE A MODULE GLOBAL — `afirewall.args = SimpleNamespace(ip=...)` —
        # because get_external_interface could not be called without one. That the test had to
        # invent a parsed command line to ask a question about routing is the whole argument for
        # passing `ip` instead of reaching for it; the stub below is what is left when it does.
        original, afirewall.ip_json = afirewall.ip_json, lambda ip, *a: fixtures.get(tuple(a), [])
        try:
            return afirewall.get_external_interface('/usr/bin/ip', destination, family)
        finally:
            afirewall.ip_json = original

    def testIpv6IsFoundOnANormallyNamedInterface(self):
        for name in ('ens3', 'eth0', 'enp4s0', 'eno1'):
            with self.subTest(device=name):
                found = self.discover(afirewall.Family.IPV6, '2001:4860:4860::8888', {
                    ('route', 'get', 'to', '2001:4860:4860::8888'):
                        [{'dev': name, 'prefsrc': '2a01:4f8:1c1c:abcd::1'}],
                    ('addr', 'show', name):
                        [{'addr_info': [{'family': 'inet6', 'local': '2a01:4f8:1c1c:abcd::1',
                                         'prefixlen': 64, 'scope': 'global'}]}]})
                self.assertIsNotNone(found, name + ' was not discovered')
                self.assertEqual(name, found.device)

    def testTheLinkLocalAddressIsNotMistakenForTheExternalOne(self):
        """fe80::/10 is on every IPv6 interface and is never what traffic leaves from. Taking the
        first address in the list would pick it about half the time."""
        found = self.discover(afirewall.Family.IPV6, '2001:4860:4860::8888', {
            ('route', 'get', 'to', '2001:4860:4860::8888'):
                [{'dev': 'ens3', 'prefsrc': '2a01:4f8:1c1c:abcd::1'}],
            ('addr', 'show', 'ens3'):
                [{'addr_info': [{'family': 'inet6', 'local': 'fe80::1', 'prefixlen': 64,
                                 'scope': 'link'},
                                {'family': 'inet6', 'local': '2a01:4f8:1c1c:abcd::1',
                                 'prefixlen': 64, 'scope': 'global'}]}]})
        self.assertEqual('2a01:4f8:1c1c:abcd::1', str(found.address))
        self.assertEqual('2a01:4f8:1c1c:abcd::/64', str(found.network))

    def testTheNetworkComesFromTheAddressTheRouteChose(self):
        """An interface commonly carries more than one address in a family. The one that matters is
        the one the route picked, not the one listed first."""
        found = self.discover(afirewall.Family.IPV4, '8.8.8.8', {
            ('route', 'get', 'to', '8.8.8.8'): [{'dev': 'eth0', 'prefsrc': '10.1.2.3'}],
            ('addr', 'show', 'eth0'):
                [{'addr_info': [{'family': 'inet', 'local': '192.0.2.7', 'prefixlen': 24,
                                 'scope': 'global'},
                                {'family': 'inet', 'local': '10.1.2.3', 'prefixlen': 16,
                                 'scope': 'global'}]}]})
        self.assertEqual('10.1.0.0/16', str(found.network))

    def testNoRouteIsNotAnInterface(self):
        self.assertIsNone(self.discover(afirewall.Family.IPV6, '2001:4860:4860::8888', {}))

    def testDiscoveryTargetsAreDocumentationAddresses(self):
        """The defaults handed to `ip route get`, pinned so nobody helpfully restores a real one.

        No packet is sent - this is a routing table lookup - so the usual objection to a public
        resolver's address does not apply. What does is that a host may carry a SPECIFIC route for
        a real service: a split-tunnel VPN forcing DNS down the tunnel makes discovery return the
        tunnel's device, and then the SPOOFING chain is qualified by the wrong interface and the
        spoof list subtracted against the wrong network, with nothing to show for it.

        RFC 5737 and RFC 3849 addresses name no service, so nothing routes them for a service's
        sake and the lookup follows the default route - which is the question being asked.
        """
        from ipaddress import ip_address, ip_network
        defaults = {a.dest: a.default for a in afirewall.get_parser()._actions}
        self.assertIn(ip_address(defaults['ipv4dest']), ip_network('192.0.2.0/24'),
                      'the IPv4 discovery target is not an RFC 5737 documentation address')
        self.assertIn(ip_address(defaults['ipv6dest']), ip_network('2001:db8::/32'),
                      'the IPv6 discovery target is not an RFC 3849 documentation address')


class TestFamilySpecificPorts(unittest.TestCase):
    """Ports that are not the same in both families.

    A REGRESSION TEST FOR A COPY-PASTE THAT COST A HOST ITS ADDRESS. Nearly every service uses the
    same port in both families, so an IPv6 template is usually a correct copy of its IPv4 sibling
    with the selectors changed. DHCP is the exception: IPv4 uses 67/68 and DHCPv6 uses 547/546.
    templates/ipv6/outbound/dhcp.rules was a byte-for-byte copy, so on a host with a DHCPv6 lease
    the renewal was refused by the outbound policy drop and the address lapsed when the lease ran
    out. Nothing failed loudly - the host simply stopped having IPv6.

    Stated as a rule rather than one assertion about DHCP: where the families agree, the ports must
    match, and where they cannot agree, they must not.
    """

    SAME_IN_BOTH = None          # every service not listed below
    MUST_DIFFER = {'dhcp'}       # 67/68 against 547/546

    def ports(self, text):
        # Port 0 is PORT_ZERO's, not a service's: that chain is in base.rules on every render and
        # drops port zero in either direction, so it turns up in anything read off the whole file.
        return sorted(set(re.findall(r'\b[ds]port (\d+)', text)) - {'0'})

    def rendered(self, family, service, direction='outbound'):
        """This service alone, as the ruleset actually receives it.

        READ FROM THE RENDERED OUTPUT AND NOT FROM A FILE, since chapter 8: a service's ports live
        in one record and reach the ruleset through a renderer, so a test reading a template would
        be asking a file that no longer decides anything.
        """
        return render(family, **{direction: [service]})

    def testPortsMatchAcrossFamiliesExceptWhereTheyCannot(self):
        for (direction, service) in sorted(afirewall.load_catalogue('.')):
            with self.subTest(service=direction + '/' + service):
                four_ports = self.ports(self.rendered('ipv4', service, direction))
                six_ports = self.ports(self.rendered('ipv6', service, direction))
                if True:
                    if service in self.MUST_DIFFER:
                        self.assertNotEqual(
                            four_ports, six_ports,
                            service + ' uses the same ports in both families, and it must not - '
                            'IPv4 DHCP is 67/68 and DHCPv6 is 547/546, so an identical copy leaves '
                            'a host unable to renew its lease')
                    else:
                        self.assertEqual(
                            four_ports, six_ports,
                            service + ' uses different ports in each family, which is either a '
                            'typo or a service that belongs in MUST_DIFFER with a reason')

    def testDhcpv6UsesTheDhcpv6Ports(self):
        """The specific numbers, because 'differs from IPv4' would also be satisfied by a typo."""
        self.assertEqual(['546', '547'], self.ports(self.rendered('ipv6', 'dhcp')))
        self.assertEqual(['67', '68'], self.ports(self.rendered('ipv4', 'dhcp')))

    def testDhcpRepliesDoNotDependOnConntrack(self):
        """The reply to a DHCP request is not reliably the return direction of it.

        A client that broadcasts or multicasts its request gets an answer from the server's own
        unicast address, so conntrack sees no matching tuple and the reply arrives INVALID or NEW.
        A rule asking for ESTABLISHED then never matches, the reply dies on the chain policy
        without touching a counter, and the lease runs out with nothing to say why.

        MEASURED IN BOTH FAMILIES, AND THEY DID NOT AGREE — which is the reason this test states a
        rule rather than a fact. On the host this was found on:

          IPv6  firewall up, a ten-minute lease counted 600 down to 25 and never renewed; firewall
                stopped, back to 578 within seconds. A forced reconfigure with the firewall up lost
                the address entirely and did not get it back.
          IPv4  renewed AND fully re-acquired through the same firewall - the journal shows `DHCP
                lease lost` followed by `acquired from 169.254.0.2` - because networkd talks
                unicast to a server it already knows, so the tuple matches and ESTABLISHED holds.

        So IPv4 was not broken, and an earlier version of this docstring said it was. What is true
        is that IPv4 works BY THE CLIENT'S CHOICE of unicast, not by anything the rule guarantees.
        A firewall that depends on which destination a DHCP client picks is a firewall that works
        until the client changes, and the port pair is what it can say for itself.
        """
        for family, server, client in (('ipv4', '67', '68'), ('ipv6', '547', '546')):
            with self.subTest(family=family):
                rules = [l.strip() for l in self.rendered(family, 'dhcp').splitlines()
                         if 'sport ' + server in l]
                self.assertTrue(rules, family + ' has no inbound DHCP reply rule at all')
                for rule in rules:
                    self.assertNotIn(
                        'ct state', rule,
                        family + ' gates the DHCP reply on conntrack state, which holds only while '
                        'the client happens to unicast: ' + rule)
                    self.assertIn(
                        'dport ' + client, rule,
                        family + ' does not match the DHCP client port: ' + rule)

    def testDhcpNeedsBothDirectionsFromOneFlag(self):
        """One flag opens both halves, and for DHCP the inbound half is a real rule.

        Every other service's inbound line under `outbound.<service>` is a conntrack reply path.
        DHCP's cannot be, so `outbound.dhcp` opens an actual inbound accept - which is right, and
        is worth pinning: splitting it into `inbound.dhcp` and `outbound.dhcp` would make enabling
        one and not the other a way to lose an address, and nothing would say so.
        """
        for family, server in (('ipv4', '67'), ('ipv6', '547')):
            lines = self.rendered(family, 'dhcp').splitlines()
            with self.subTest(family=family):
                self.assertTrue(any('sport ' + server in l for l in lines),
                                family + ': no inbound half is opened by outbound.dhcp')
                self.assertTrue(any('dport ' + server in l for l in lines),
                                family + ': no outbound half is opened by outbound.dhcp')
                self.assertNotIn(('inbound', 'dhcp'), afirewall.load_catalogue('.'),
                                 family + ': DHCP has been split across two flags, so enabling one '
                                 'and not the other silently costs the host its address')
