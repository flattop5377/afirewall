from afirewall import afirewall
from jinja2 import Environment, FileSystemLoader
import os
import unittest

SPOOFED = ['10.0.0.0/8', '192.168.0.0/16']

def render(family, device='eth0', spoofed=None):
    env = Environment(loader=FileSystemLoader('templates'))
    return env.get_template(family + '/base.rules').render(
        EXTERNAL_DEVICE=device,
        EXTERNAL_ADDRESS='203.0.113.7',
        LOCAL_NETWORK='203.0.113.0/24',
        SPOOFED_NETWORKS=SPOOFED if spoofed is None else spoofed,
        inbound={}, outbound={})

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
            for network in SPOOFED:
                self.assertIn('iifname eth0 {sel} {net}'.format(sel=selector, net=network),
                              render(family),
                              family + ' drops ' + network + ' without naming the device it arrived on')

    def testSpoofDropsNameTheDetectedDeviceNotAHardcodedOne(self):
        """EXTERNAL_DEVICE comes from the route to the internet, so it differs per host."""
        self.assertIn('iifname ens3 ip saddr 10.0.0.0/8', render('ipv4', device='ens3'))

    def testIpv6UsesTheIpv6Selector(self):
        """`ip saddr` does not parse inside an ip6 table. It has gone unnoticed because
        there is no lists/spoofed_IPV6_networks.list, so the loop has never emitted a row."""
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

if __name__ == '__main__':
    unittest.main()
