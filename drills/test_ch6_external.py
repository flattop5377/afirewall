"""Chapter 6 drills — whether the untrusted interface is stated or guessed.

The argument is in ``spec/diagrams/chapter-06-external-interface.md``.

**RED, AND THAT IS THE STATE.** Nothing here is built. Every drill names what is absent rather than
skipping, because the reading is trivial and what it finds is that the feature does not exist —
which is evidence, not the lack of it.
"""

import pathlib
import re
import sys

import pytest

from undrilled import unwatched

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from afirewall import afirewall  # noqa: E402
MAIN = ROOT / "afirewall" / "afirewall.py"

#: Where a stated external interface would be read from. THE PATH IS NOT THE POINT — what matters
#: is that it sits in the base directory, because that is what makes it persist exactly as the rules
#: do (ch6-3). Any of these satisfies the claim.
CANDIDATES = ("interfaces.conf", "external.conf", "external")


def source():
    return MAIN.read_text()


@pytest.mark.proves("ch6-1", depth="unit")
def test_hosts_have_more_than_one_interface():
    unwatched("ch6-1", "the interfaces each host carries and which of them the SPOOFING chain "
                       "names — taken on the hosts on 2026-08-16 and found to be two to five "
                       "against one, but it is a reading of hosts rather than of this repository "
                       "and belongs with whoever runs them")


@pytest.mark.proves("ch6-2", depth="structural")
def test_the_external_interface_can_be_stated():
    """Trust is policy and the routing table is not a trust database. The default route says where
    packets go, not which network is hostile, and on every host measured a full-tunnel VPN is one
    `AllowedIPs` away from making those two answers differ."""
    text = source()
    assert re.search(r"external.{0,20}(conf|file|stated|declared)", text, re.I), (
        "nothing reads a stated external interface, so the only answer available is the one "
        "inferred from the default route — which is right until a host routes its default down a "
        "tunnel, and then applies the anti-spoofing rules to the overlay instead of to the NIC")


@pytest.mark.proves("ch6-3", depth="structural")
def test_it_is_read_from_the_base_directory():
    """How it persists decides where it lives. netfilter-persistent runs the plugin at boot with no
    arguments, so a flag does not survive; a unit drop-in or an environment file would be a second
    persistence mechanism beside the one this package already has. The base directory is read at
    generate time, which is the only shape that persists the way the rules do."""
    text = source()
    assert re.search(r"basedir|base_directory", text), "the base directory is not consulted at all"
    reads_one = any(f"'{c}'" in text or f'"{c}"' in text for c in CANDIDATES)
    assert reads_one, (
        "no file in the base directory states the external interface. It cannot be a command-line "
        f"flag - the plugin is invoked with none at boot. Expected one of: {list(CANDIDATES)}")


@pytest.mark.proves("ch6-4", depth="structural")
def test_it_is_not_a_key_in_the_service_configuration():
    """afirewall.conf is composed by appending service flags and a configuration manager restores
    ONE BASELINE SHARED BY EVERY HOST before each run. A per-host fact put there is either erased
    by the restore every converge, or forces the baseline to stop being one file."""
    conf = (ROOT / "afirewall.conf").read_text()
    intruders = []
    for line in conf.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        if not re.fullmatch(r"(in|out)bound\.[a-z0-9]+:\s*(enable|disable)", line):
            intruders.append(line)
    assert not intruders, (
        f"afirewall.conf carries something that is not a service flag: {intruders}. A per-host "
        "fact there is erased by the restore a configuration manager runs at the start of every "
        "converge, because that baseline is one file for every host.")


@pytest.mark.proves("ch6-5", depth="structural")
def test_saying_nothing_still_works():
    """A host with one interface must need no configuration — that is what the package is for, and
    the discovery it already does is right for it on eight hosts out of eight."""
    text = source()
    assert "get_external_interface" in text, (
        "discovery is gone, so a host that states nothing has no external interface at all and a "
        "single-NIC installation stops working out of the box")


@pytest.mark.proves("ch6-6", depth="structural")
def test_a_named_interface_that_is_not_there_is_refused():
    """The failure mode of a wrong statement must not be a silently misapplied rule, which is the
    whole complaint against guessing. A fallback to discovery would turn a typo into exactly that."""
    # MATCHED ON THE MESSAGE, NOT ON PROXIMITY. The first version of this looked for `sys.exit`
    # within 200 characters of the word "interface" and passed immediately — on an unrelated exit
    # about a ruleset failing to load, followed by "interface" in the next function's signature.
    # A drill that passes for the wrong reason is the fault this whole spec is about, so this asks
    # for a refusal that says what it is refusing.
    text = source()
    refusal = re.search(
        r"(sys\.exit|raise)[^\n]{0,400}?"
        r"(no such (device|interface)|does not exist|is not an? (device|interface)|not on this host)",
        text, re.I)
    assert refusal, (
        "nothing refuses a stated interface the host does not have, so a typo either falls back to "
        "discovery or generates rules naming a device that is not there — quiet and plausible, "
        "which is the failure this chapter exists to remove")


@pytest.mark.proves("ch6-7", depth="structural")
def test_a_protection_exists_that_names_no_interface():
    """ufw's check, taken alongside rather than instead of the spoof list.

    THE CLAIM IS NARROWER THAN AN EARLIER DRAFT SAID. Writing the rule is what showed it: this does
    not compensate for a wrong external interface, because a spoofed packet is still addressed to
    us and would pass here. What is true is that it needs no interface named at all, so it is a
    protection whose correctness does not depend on the trust statement being right — two
    protections, not a protection and its fallback.
    """
    families = sorted(p for p in (ROOT / "templates").rglob("base.rules")
                      if "fib daddr type" in p.read_text() and "NOT_LOCAL" in p.read_text())
    assert len(families) == 2, (
        "a base ruleset does not drop packets that were never addressed to this host. The check "
        f"names no interface, so nothing about it can be got wrong by naming one. Found in "
        f"{len(families)} of 2 families.")
    # AND COUNTED, per ch1-9. On a normal host the routing decision has already sent everything
    # addressed elsewhere to the forward hook, so this may never fire - and a drop rule that
    # matches nothing looks exactly like one that is working.
    for path in families:
        assert "NUMBER_OF_NOT_LOCAL_DROPPED" in path.read_text(), (
            f"{path.name} drops not-local traffic without a named counter, so whether the rule has "
            "ever fired cannot be asked")


@pytest.mark.proves("ch6-8", depth="integration")
def test_the_rules_land_on_the_interface_the_operator_meant():
    unwatched("ch6-8", "a host with a tunnel, a bridge and a NIC, with its default route moved to "
                       "the tunnel, checked for which interface the SPOOFING chain names — which "
                       "is ch6-U2 and needs a disposable host rather than a reading here")


@pytest.mark.proves("ch6-9", depth="unit")
def test_a_host_can_say_its_private_space_is_bigger_than_its_subnet():
    """The spoof chain subtracts the interface's own network, which is right for a host whose
    tunnel is its own interface and wrong for one behind a router that terminates the tunnel.

    MEASURED ON a host BEFORE IT COST ANYTHING, 2026-08-17. Every live connection to the deployment's log
    collector, backup server and alerter arrived from 203.0.113.0/24 on the ORDINARY LAN
    interface — the a router router terminates the tunnel and forwards, so the packets reach a host
    already decapsulated with a private source from a subnet it is not on. Its computed spoof list
    contained 203.0.113.0/21. Rolling the firewall out would have dropped syslog, borg and every
    alerter check-in from all seven VPS hosts, at priority raw, ahead of any accept rule.

    Silence still means the interface's own subnet and nothing else, which is what keeps every host
    that does not need this working without saying anything.
    """
    import tempfile
    from ipaddress import ip_network
    interface = afirewall.Interface("198.51.100.20", "198.51.100.0/24", "eno1",
                                    afirewall.Family.IPV4.value)
    tunnel = ip_network("203.0.113.0/24")

    caught = lambda nets: any(tunnel.subnet_of(n) for n in nets)
    assert caught(afirewall.get_spoofed_networks(str(ROOT), interface)), (
        "with nothing stated, a private subnet this host is not on is expected to be dropped — if "
        "it is not, this test is no longer measuring anything")

    with tempfile.TemporaryDirectory() as base:
        (pathlib.Path(base) / "lists").symlink_to(ROOT / "lists")
        (pathlib.Path(base) / "local_networks.conf").write_text("203.0.113.0/21\n")
        nets = afirewall.get_spoofed_networks(base, interface)
        assert not caught(nets), (
            "a network the operator stated as legitimately reaching this host is still in the "
            "spoof list, so the rule drops traffic the configuration says to accept")
        assert any(n == ip_network("10.0.0.0/8") for n in nets), (
            "stating one network removed others: 10.0.0.0/8 is unrelated and must still be dropped")

        (pathlib.Path(base) / "local_networks.conf").write_text("not-a-network\n")
        with pytest.raises(SystemExit) as refused:
            afirewall.get_spoofed_networks(base, interface)
        assert "not a network" in str(refused.value), (
            "a line that does not parse was skipped rather than refused, which produces a host "
            f"dropping traffic its own config admits: {refused.value}")
