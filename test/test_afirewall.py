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
    return env.get_template(family + '/base.rules').render(
        EXTERNAL_DEVICE=device,
        EXTERNAL_ADDRESS='203.0.113.7',
        LOCAL_NETWORK='203.0.113.0/24',
        SPOOFED_NETWORKS=SPOOFED[family] if spoofed is None else spoofed,
        inbound={name: True for name in inbound},
        outbound={name: True for name in outbound})

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

    def testEveryIncludeResolvesToAFileThatExists(self):
        """An include naming a file that is not there costs nothing until the key guarding it
        is switched on - and then raises TemplateNotFound at the moment somebody is trying to
        bring a firewall up. base.rules carried three of them (orport, dirport, bitcoin, the
        last a near-miss for btc.rules), each unreachable only because no config key set it."""
        for family in FAMILIES:
            source = open('templates/' + family + '/base.rules').read()
            included = re.findall(r"\{% include '([^']+)' %\}", source)
            self.assertTrue(included, family + '/base.rules includes nothing at all')
            for path in included:
                self.assertTrue(os.path.isfile('templates/' + path),
                                family + '/base.rules includes ' + path + ', which is not there')
                self.assertTrue(path.startswith(family + '/'),
                                family + '/base.rules includes ' + path + ' from another family')

    def testEveryConfigKeyHasATemplateBehindIt(self):
        """A key with no template is a switch wired to nothing. Turn it on and either nothing
        happens - which reads as a firewall rule that is in force and is not - or the include
        raises TemplateNotFound while a firewall is being brought up. `inbound.bitcoin` was
        the second kind, a near-miss for the btc.rules that does exist."""
        declared = services()
        for side in ('inbound', 'outbound'):
            for service in sorted(declared[side]):
                found = ['templates/{f}/{s}/{n}.rules'.format(f=f, s=side, n=service)
                         for f in FAMILIES
                         if os.path.isfile('templates/{f}/{s}/{n}.rules'.format(f=f, s=side, n=service))]
                self.assertTrue(found,
                                side + '.' + service + ' is in afirewall.conf with no template '
                                'in either family')

    def testEveryTemplateHasAConfigKeyToTurnItOn(self):
        """The same skew from the other side. A template no key names cannot be switched on,
        so it is work that looks like coverage and provides none."""
        declared = services()
        for family in FAMILIES:
            for side in ('inbound', 'outbound'):
                directory = 'templates/{f}/{s}'.format(f=family, s=side)
                for name in sorted(os.listdir(directory)):
                    if not name.endswith('.rules'):
                        continue
                    service = name[:-len('.rules')]
                    self.assertIn(service, declared[side],
                                  directory + '/' + name + ' has no ' + side + '.' + service +
                                  ' key in afirewall.conf')

    def testEveryServiceTemplateIsReachable(self):
        """The other direction: a template nothing includes is a rule set nobody can turn on,
        which reads as coverage while providing none."""
        for family in FAMILIES:
            source = open('templates/' + family + '/base.rules').read()
            included = set(re.findall(r"\{% include '([^']+)' %\}", source))
            for side in ('inbound', 'outbound'):
                directory = 'templates/{family}/{side}'.format(family=family, side=side)
                for name in sorted(os.listdir(directory)):
                    if not name.endswith('.rules'):
                        continue
                    path = '{family}/{side}/{name}'.format(family=family, side=side, name=name)
                    self.assertIn(path, included, path + ' exists but nothing includes it')

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
