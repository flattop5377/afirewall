#!/usr/bin/env python3
"""A two-namespace lab that fires known-bad traffic at a real ruleset and reads the counters.

WHY THIS EXISTS. `ch1-9` says a named counter is what separates a claim from a rule — `nft list
counters` tells you whether a drop has ever fired, so a rule that matches nothing is visible rather
than assumed. That is only true if somebody reads them against traffic they sent on purpose. Read
against ambient traffic a zero says nothing: on 2026-08-17 four of a host's five counters were zero,
one of them because the chain sat behind `nf_defrag` and could not fire, and nothing on the host
could tell the two apart.

WHY NOT ON A FLEET HOST. Every VPS here sits behind a provider's own firewall, which neither this
repository nor `ansible` can see or read (`ansible` ch5 records the same wall from the other side).
A counter that stays at zero there has three possible causes — the rule works, the rule is
unreachable, or the provider dropped the packet upstream — and the host cannot distinguish them.
Testing against production would also mean opening ports to bounce traffic off, which is a firewall
change made in order to test a firewall.

So the target is a network namespace: no provider in front of it, nothing else on the wire, and
every packet that arrives is one this script sent.

WHAT IT PROVES AND WHAT IT DOES NOT. It proves a rule matches the traffic it names and that the
counter moves. It does not prove the ruleset is right for a real host — the addresses are the lab's
and the traffic is synthetic. `ch1-U2` (whether a rate limit refuses abuse without refusing use) is
a harder question this does not answer, though it is the harness that could.

    sudo python3 tools/lab.py            run every case
    sudo python3 tools/lab.py --keep     leave the namespaces up to poke at
"""

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = "afwlab-t"
ATTACKER = "afwlab-a"
# THE THIRD NAMESPACE IS WHAT MAKES THIS A FORWARDING LAB (ch4-1). With two, the target terminates
# everything and only `input` and `output` are ever exercised - which is exactly the blind spot
# chapter 4 is about, reproduced in the instrument meant to find it. A service BEHIND the target
# turns the target into a router for its own service, which is the shape a namespaced host has.
SERVICE = "afwlab-s"

# ADDRESSES CHOSEN AGAINST THE SPOOF LISTS, which is not a detail. The obvious lab ranges —
# 198.51.100.0/24 and 2001:db8::/32 — are both ON those lists, so a lab built on them has every
# packet dropped by SPOOFING before any other chain sees it, and four cases fail for one reason.
# 100.64.0.0/10 and 2a00:dead::/64 are absent from both lists.
V4_NET, V4_TARGET, V4_ATTACKER = "100.64.0.0/24", "100.64.0.1", "100.64.0.2"
V6_NET, V6_TARGET, V6_ATTACKER = "2a00:dead::/64", "2a00:dead::1", "2a00:dead::2"
# The service network, behind the target. Routed rather than translated, which is the case ch4
# covers - ch4-U4 is the translated one, and this package has no nat table to test it with.
SVC_NET, SVC_TARGET, SVC_HOST = "10.99.0.0/24", "10.99.0.1", "10.99.0.2"
FORWARDED_PORT = 1965
UNDECLARED_PORT = 2222
# ON the lists, for the one case that wants to be caught by SPOOFING.
V4_SPOOFED, V6_SPOOFED = "203.0.113.5", "2001:db8::5"


def run(*argv, ns=None, check=True, **kw):
    argv = (["ip", "netns", "exec", ns] if ns else []) + list(argv)
    return subprocess.run(argv, capture_output=True, text=True, check=check, **kw)


def teardown():
    for ns in (TARGET, ATTACKER, SERVICE):
        subprocess.run(["ip", "netns", "del", ns], capture_output=True)


def setup():
    """Two namespaces, one veth between them, and a default route so afirewall finds an interface.

    The default route is not decoration: afirewall discovers its external device by asking the
    routing table which one reaches 192.0.2.1, so a namespace without one renders nothing and
    exits — correctly, and unhelpfully for a lab.
    """
    teardown()
    for ns in (TARGET, ATTACKER, SERVICE):
        run("ip", "netns", "add", ns)
    run("ip", "link", "add", "t0", "netns", TARGET, "type", "veth", "peer", "a0", "netns", ATTACKER)
    for ns, dev, v4, v6, peer4, peer6 in (
            (TARGET, "t0", V4_TARGET, V6_TARGET, V4_ATTACKER, V6_ATTACKER),
            (ATTACKER, "a0", V4_ATTACKER, V6_ATTACKER, V4_TARGET, V6_TARGET)):
        run("ip", "addr", "add", f"{v4}/{V4_NET.split('/')[1]}", "dev", dev, ns=ns)
        run("ip", "-6", "addr", "add", f"{v6}/{V6_NET.split('/')[1]}", "dev", dev, "nodad", ns=ns)
        run("ip", "link", "set", dev, "up", ns=ns)
        run("ip", "link", "set", "lo", "up", ns=ns)
        run("ip", "route", "add", "default", "via", peer4, ns=ns)
        run("ip", "-6", "route", "add", "default", "via", peer6, ns=ns)
    # The attacker must be allowed to send a source address that is not its own.
    run("ip", "netns", "exec", ATTACKER, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")

    # The service leg, and the routes that make the target a router rather than an endpoint.
    run("ip", "link", "add", "t1", "netns", TARGET, "type", "veth", "peer", "s0", "netns", SERVICE)
    run("ip", "addr", "add", f"{SVC_TARGET}/24", "dev", "t1", ns=TARGET)
    run("ip", "link", "set", "t1", "up", ns=TARGET)
    run("ip", "addr", "add", f"{SVC_HOST}/24", "dev", "s0", ns=SERVICE)
    run("ip", "link", "set", "s0", "up", ns=SERVICE)
    run("ip", "link", "set", "lo", "up", ns=SERVICE)
    run("ip", "route", "add", "default", "via", SVC_TARGET, ns=SERVICE)
    run("ip", "route", "add", SVC_NET, "via", V4_TARGET, ns=ATTACKER)
    run("ip", "netns", "exec", TARGET, "sysctl", "-qw", "net.ipv4.ip_forward=1")


def load_ruleset(basedir):
    """Render the WORKING TREE's templates inside the target and load them.

    The basedir carries templates/ and lists/ so the checkout is what is tested, not whatever
    package happens to be installed on the machine running this.

    /var/lib/afirewall is bind-mounted over with a scratch directory. `ip netns exec` unshares the
    mount namespace, so that mount is invisible outside this process and the workstation does not
    acquire the state directory of a service it does not run.
    """
    shutil.copytree(ROOT / "templates", pathlib.Path(basedir) / "templates")
    shutil.copytree(ROOT / "lists", pathlib.Path(basedir) / "lists")
    shutil.copy(ROOT / "afirewall.conf", pathlib.Path(basedir) / "afirewall.conf")
    shutil.copy(ROOT / "services.toml", pathlib.Path(basedir) / "services.toml")
    # A FORWARDED SERVICE, DECLARED HERE RATHER THAN SHIPPED. It is the lab's own service and has
    # no business in the package's catalogue - but declaring it exercises ch4-2's conditional
    # chain, ch4-4's derived pair, and ch8-9's merge, all of which are the same act.
    with open(pathlib.Path(basedir) / "services.toml", "a") as file:
        file.write(f'''
[[service]]
name = "labsvc"
direction = "forward"
title = "LABSVC Rules"
ports = ["tcp/{FORWARDED_PORT}"]
to = "{SVC_HOST}"
''')
    with open(pathlib.Path(basedir) / "afirewall.conf", "a") as file:
        file.write("forward.labsvc: enable\n")
    generated = pathlib.Path(basedir) / "generated"
    generated.mkdir()
    script = (f"mkdir -p /var/lib/afirewall && mount --bind {generated} /var/lib/afirewall && "
              f"{sys.executable} {ROOT}/afirewall/afirewall.py -b {basedir} regenerate")
    done = run("ip", "netns", "exec", TARGET, "unshare", "-m", "sh", "-c", script, check=False)
    if done.returncode != 0:
        sys.exit(f"could not build a ruleset in the lab:\n{done.stdout}\n{done.stderr}")
    # regenerate wrote the files under the bind mount, which is gone with that process. Load the
    # copies it left in the scratch directory instead.
    for nft in sorted(generated.glob("ipv[46].nft")):
        run("nft", "-f", str(nft), ns=TARGET)
    return done.stdout


def counters():
    """"<family> <table> <name>" -> packets.

    KEYED ON THE TABLE, and leaving it out cost an hour. `NUMBER_OF_INVALID_FLAGS_DROPPED` is
    defined in the inbound table AND the outbound one, so a key of family+name collapses the two
    and keeps whichever nft printed last — the outbound copy, which inbound traffic never touches
    and which therefore reads zero forever. The two cases that use that counter reported FAIL
    against a firewall that was working, which is this harness making exactly the error it exists
    to detect. The drill next door had the same collision on chain names.
    """
    out = json.loads(run("nft", "-j", "list", "counters", ns=TARGET).stdout)
    return {f"{o['counter']['family']} {o['counter']['table']} {o['counter']['name']}":
            o["counter"]["packets"]
            for o in out["nftables"] if "counter" in o}


# EACH CASE IS ONE SENTENCE OF SCAPY AND THE COUNTER IT MUST MOVE. Sent from the attacker namespace
# so the packets arrive on the target's external device, which is what every one of these rules is
# qualified by.
CASES = [
    ("ip a-firewall-inbound-ipv4 NUMBER_OF_SPOOFS_DROPPED", "v4 source on the spoof list",
     f'IP(src="{V4_SPOOFED}",dst="{V4_TARGET}")/TCP(dport=22,flags="S")'),
    ("ip6 a-firewall-inbound-ipv6 NUMBER_OF_SPOOFS_DROPPED", "v6 source on the spoof list",
     f'IPv6(src="{V6_SPOOFED}",dst="{V6_TARGET}")/TCP(dport=22,flags="S")'),
    ("ip a-firewall-inbound-ipv4 NUMBER_OF_INVALID_FLAGS_DROPPED", "v4 TCP with no flags at all (NULL scan)",
     f'IP(src="{V4_ATTACKER}",dst="{V4_TARGET}")/TCP(dport=22,flags=0)'),
    ("ip6 a-firewall-inbound-ipv6 NUMBER_OF_INVALID_FLAGS_DROPPED", "v6 TCP with SYN and FIN together",
     f'IPv6(src="{V6_ATTACKER}",dst="{V6_TARGET}")/TCP(dport=22,flags="FS")'),
    ("ip a-firewall-inbound-ipv4 NUMBER_OF_PORT_ZERO_SEGMENTS_DROPPED", "v4 TCP to port 0",
     f'IP(src="{V4_ATTACKER}",dst="{V4_TARGET}")/TCP(dport=0,flags="S")'),
    ("ip6 a-firewall-inbound-ipv6 NUMBER_OF_PORT_ZERO_SEGMENTS_DROPPED", "v6 UDP from port 0",
     f'IPv6(src="{V6_ATTACKER}",dst="{V6_TARGET}")/UDP(sport=0,dport=53)'),
    # THE TWO THIS WHOLE EXERCISE IS ABOUT. A non-first fragment: offset non-zero, so it is not the
    # first and not an RFC 6946 atomic fragment either.
    ("ip a-firewall-inbound-ipv4 NUMBER_OF_FRAGMENTS_DROPPED", "v4 non-first fragment",
     f'IP(src="{V4_ATTACKER}",dst="{V4_TARGET}",proto=17,frag=64,flags=0)/Raw(load="A"*64)'),
    ("ip6 a-firewall-inbound-ipv6 NUMBER_OF_FRAGMENTS_DROPPED", "v6 non-first fragment",
     f'IPv6(src="{V6_ATTACKER}",dst="{V6_TARGET}")/IPv6ExtHdrFragment(offset=8,m=0,nh=17)'
     f'/Raw(load="A"*64)'),
]


# THE INTERPRETER IS CHOSEN, NOT ASSUMED, and assuming it produced the worst possible failure.
# `sys.executable` is whatever is running this — under `plumb board` that is the repository's
# .venv, which carries jinja2 from requirements.txt and no scapy. `fire()` then failed, the
# packets were never sent, every counter read zero, and the harness reported EIGHT FAILING RULES
# against a firewall that was working perfectly. An instrument that blames the thing it is
# measuring for its own fault is the exact failure this lab exists to catch, and it made it on its
# first run under a different launcher.
def scapy_interpreter():
    """The first interpreter that can actually import scapy, or None."""
    for candidate in (sys.executable, "/usr/bin/python3", shutil.which("python3")):
        if candidate and subprocess.run([candidate, "-c", "import scapy"],
                                        capture_output=True).returncode == 0:
            return candidate
    return None


def crossing(port, expect):
    """Can the attacker reach the service namespace on this port, through the target?

    THE ONLY CASE IN THIS LAB THAT IS NOT A COUNTER. A forwarded service is admitted or refused by
    a chain at a hook the rest of the file never touches, and what a counter would say about it is
    that a rule matched - not that a connection completed. Reachability is the claim (ch4-7), so
    reachability is what is measured.
    """
    listener = subprocess.Popen(
        ["ip", "netns", "exec", SERVICE, sys.executable, "-c",
         "import socket,threading,time\n"
         "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
         f"s.bind(('{SVC_HOST}',{port})); s.listen(1)\n"
         "threading.Thread(target=lambda:(s.accept()[0].send(b'x'),),daemon=True).start()\n"
         "time.sleep(6)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        probe = run("ip", "netns", "exec", ATTACKER, sys.executable, "-c",
                    "import socket,sys\n"
                    f"socket.create_connection(('{SVC_HOST}',{port}),2)\n",
                    check=False, timeout=10)
        reached = probe.returncode == 0
    finally:
        listener.kill()
        listener.wait()
    return reached == expect, reached


def fire(python, expression):
    """Send it, and raise if it was not sent. A silent sender is a harness that lies."""
    script = ("import logging; logging.getLogger('scapy').setLevel(logging.ERROR)\n"
              "from scapy.all import *\n"
              f"send({expression}, count=3, verbose=0)\n")
    done = run("ip", "netns", "exec", ATTACKER, python, "-c", script, check=False)
    if done.returncode != 0:
        raise RuntimeError(
            f"the lab could not SEND this, so nothing here is evidence about the firewall:\n"
            f"  {expression}\n{done.stderr.strip()}")
    return done


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true",
                        help="leave the namespaces up afterwards")
    parser.add_argument("--teardown-only", action="store_true",
                        help="remove namespaces a previous --keep left behind, and do nothing else")
    args = parser.parse_args()
    if args.teardown_only:
        teardown()
        return 0
    if os.geteuid() != 0:
        sys.exit("this needs root: it creates network namespaces and loads a ruleset into one")
    python = scapy_interpreter()
    if python is None:
        # EXIT 2, NOT 1. "This machine cannot run the lab" and "a rule failed" are different
        # answers and a caller has to be able to tell them apart — a drill that read the second
        # for the first would report the firewall broken on any host without scapy.
        print("no interpreter here can import scapy, so no traffic can be sent and nothing this "
              "would print would be evidence. `apt install python3-scapy`, or add it to the venv "
              "this is running from.", file=sys.stderr)
        return 2

    basedir = tempfile.mkdtemp(prefix="afwlab-")
    failures = []
    try:
        setup()
        print(load_ruleset(basedir).strip())
        chains = run("nft", "list", "tables", ns=TARGET).stdout.split("\n")
        print(f"\nlab up — {len([c for c in chains if c.strip()])} tables in {TARGET}\n")

        print(f"sending with {python}\n")
        before = counters()
        for name, what, expression in CASES:
            fire(python, expression)
            after = counters()
            ok = after.get(name, 0) - before.get(name, 0) > 0
            print(f"  {'PASS' if ok else 'FAIL'}  {name:<62} {what}")
            if not ok:
                failures.append(f"{name}: {what} — sent, and the counter did not move")
            before = after
        # THE CROSSING, WHICH IS THE HOOK NOTHING ELSE IN THIS FILE REACHES (ch4-1).
        print()
        for port, expect, what in (
                (FORWARDED_PORT, True, f"declared forwarded service reaches tcp/{FORWARDED_PORT}"),
                (UNDECLARED_PORT, False,
                 f"undeclared port tcp/{UNDECLARED_PORT} is refused by the forward chain")):
            ok, reached = crossing(port, expect)
            print(f"  {'PASS' if ok else 'FAIL'}  {'crossing':<62} {what}")
            if not ok:
                failures.append(f"crossing tcp/{port}: expected "
                                f"{'reachable' if expect else 'refused'}, got "
                                f"{'reachable' if reached else 'refused'}")

        print()
        for line in sorted(counters().items()):
            print(f"  {line[0]:<62} packets={line[1]}")
    finally:
        if not args.keep:
            teardown()
            shutil.rmtree(basedir, ignore_errors=True)
        else:
            print(f"\nnamespaces left up. basedir {basedir}\n"
                  f"  sudo ip netns exec {TARGET} nft list ruleset\n"
                  f"  sudo python3 {__file__} --teardown-only")

    if failures:
        print("\n".join(["", "FAILED:"] + [f"  {f}" for f in failures]))
        return 1
    print("\nevery counter moved for the traffic that names it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
