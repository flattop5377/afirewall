"""Chapter 4 drills — whether a host that carries namespaces still refuses by default.

The argument is in ``spec/diagrams/chapter-04-namespaces.md``.

**THE BEHAVIOURAL HALF IS IN THE LAB.** `ch4-7` — a namespaced service behind the firewall rather
than beside it — is a claim about reachability, and `tools/lab.py` settles it by running a service
in a third namespace and asking whether the attacker can reach it. What is here is everything that
can be asked of the resolver: that the chain is conditional, that the crossing is derived, and that
a record with nowhere to send traffic is refused.
"""

import pathlib
import sys

import pytest

from undrilled import unwatched

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from afirewall import afirewall  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
FAMILIES = ("ipv4", "ipv6")

FORWARDED = {"name": "labsvc", "direction": "forward", "ports": ["tcp/1965"], "to": "10.99.0.2"}


def bodies(family, records, enabled):
    """service_bodies against a catalogue this test supplies, rather than the shipped one."""
    catalogue = {(r["direction"], r["name"]): r for r in records}
    config = {"inbound": {}, "outbound": {}, "forward": {}}
    for direction, name in enabled:
        config[direction][name] = True
    original = afirewall.load_catalogue
    afirewall.load_catalogue = lambda _base: catalogue
    try:
        return afirewall.service_bodies(str(ROOT), family, config)
    finally:
        afirewall.load_catalogue = original


@pytest.mark.proves("ch4-6", depth="structural")
def test_a_host_that_declares_nothing_forwards_exactly_as_it_did():
    """The compatibility claim, and the reason the chain is conditional rather than shipped
    permissive and tightened later: there is no migration to run.

    A container runtime publishing a port, a tunnel, a namespace nobody told this package about —
    all work today because the forward hook is empty, and all must keep working.
    """
    for family in FAMILIES:
        rendered = bodies(family, [FORWARDED], enabled=[])
        assert rendered["forward"] == [], (
            f"{family} produced forward rules with no forwarded service enabled, so a host that "
            "declares nothing would acquire a chain at the forward hook and start refusing traffic "
            "it has always passed")


@pytest.mark.proves("ch4-2", depth="structural")
def test_the_forward_chain_appears_only_when_something_asks_for_one():
    """The other half of ch4-6, and the two are one claim read from each end: nothing declared
    means no chain, and something declared means a chain. A template that emitted the table
    unconditionally would satisfy the first test by rendering an EMPTY chain — which is a chain at
    policy drop, and is the outage ch4-6 exists to prevent."""
    for family in FAMILIES:
        text = (ROOT / "templates" / family / "base.rules").read_text()
        assert "{% if services.forward %}" in text, (
            f"{family}/base.rules emits its forward table unconditionally. An empty chain at "
            "`policy drop` refuses everything this host forwards, so 'no services' and 'no chain' "
            "have to be the same state")
        assert "hook forward priority 20; policy drop" in text, (
            f"{family}/base.rules has no refusing chain at the forward hook, so a declared "
            "forwarded service would be admitted by rules nothing else is measured against")


@pytest.mark.proves("ch4-4", depth="structural")
def test_a_crossing_is_two_rules_derived_from_one_record():
    """MEASURED FIRST, ASSERTED SECOND. A forward chain at policy drop refused the service; these
    two rules admitted it and nothing else was needed (2026-08-17, three namespaces).

    Two rules in opposite directions from one record, which is what a reply path already is and
    what DHCP's two halves already are — so this needed no new vocabulary.
    """
    rendered = bodies("ipv4", [FORWARDED], enabled=[("forward", "labsvc")])["forward"]
    assert len(rendered) == 1, "one declared forwarded service did not produce one entry"
    crossing = rendered[0]["crossing"]
    assert crossing == [
        "ip daddr 10.99.0.2 tcp dport 1965 ct state new,established accept",
        "ip saddr 10.99.0.2 tcp sport 1965 ct state established accept",
    ], f"the crossing is not the pair the reading found: {crossing}"

    # AND NO BLANKET ACCEPT, for the reason ch1-1 refuses one on input: a forwarded service's
    # return path is admitted by its own record or not at all.
    for family in FAMILIES:
        text = (ROOT / "templates" / family / "base.rules").read_text()
        forward = text[text.index("{% if services.forward %}"):text.index("{% endif %}")]
        assert "established,related" not in forward, (
            f"{family}'s forward chain carries a blanket conntrack accept, so every flow this host "
            "forwards is admitted once anything establishes one")


@pytest.mark.proves("ch4-8", depth="structural")
def test_a_forwarded_service_must_say_where_it_goes():
    """A record with nowhere to send traffic renders a chain nothing reaches, which is the fault
    chapter 8 is named after arriving in the new direction."""
    with pytest.raises(SystemExit) as refused:
        bodies("ipv4", [{"name": "nowhere", "direction": "forward", "ports": ["tcp/9"]}],
               enabled=[("forward", "nowhere")])
    assert "to" in str(refused.value), (
        f"a forwarded service with no destination was accepted: {refused.value}")


@pytest.mark.proves("ch4-8", depth="structural")
def test_a_destination_belongs_to_one_family():
    """An IPv4 address in an ip6 table is a parse error that costs the whole family — the same
    failure as `ip saddr` in an ip6 template, which is how this package's v6 ruleset once spent
    years not loading. FOUND BY THE LAB on its first run, not by reading.

    A service reachable only over v4 having no v6 rules is a statement rather than an omission.
    """
    assert bodies("ipv6", [FORWARDED], enabled=[("forward", "labsvc")])["forward"] == [], (
        "an IPv4 destination produced ipv6 rules, which nft refuses — and it refuses the whole "
        "table, so one such record costs the host an entire address family")
    both = dict(FORWARDED, to_ipv6="2a00:dead::99")
    six = bodies("ipv6", [both], enabled=[("forward", "labsvc")])["forward"]
    assert six and "2a00:dead::99" in six[0]["crossing"][0], (
        "a record carrying a v6 destination produced no v6 crossing")


@pytest.mark.proves("ch4-3", depth="structural")
def test_there_is_no_host_level_switch_for_forwarding():
    """`forward: enable` is a global accept wearing the word 'configured'. The opt-in is a declared
    service, so the thing that says a host may forward is the same thing that says what it may
    forward — and a host that declares none has not opted in."""
    conf = (ROOT / "afirewall.conf").read_text()
    for line in conf.splitlines():
        key = line.split(":")[0].strip()
        assert key != "forward", (
            "afirewall.conf carries a bare `forward` flag. Forwarding is a relation between a "
            "destination and a port; a boolean cannot say either, and ch1-5 cannot ask who is "
            "refused when the thing described is a veth")


@pytest.mark.proves("ch4-5", depth="unit")
def test_the_namespace_governs_itself():
    unwatched("ch4-5", "somebody running a real namespaced service and finding afirewall has "
                       "written nothing inside their namespace. It is a scope decision rather "
                       "than a behaviour — what a drill could show is the absence of a thing this "
                       "package never had, which proves nothing about whether the scope is right")


@pytest.mark.proves("ch4-9", depth="structural")
def test_the_first_declaration_is_announced():
    """The cliff cannot be avoided and is a bad ending taken deliberately, so what is owed is that
    nobody arrives at it by surprise. `set_flag` says so at the moment of enabling the first one.
    """
    source = (ROOT / "afirewall" / "afirewall.py").read_text()
    assert "FIRST FORWARDED SERVICE ON THIS HOST" in source, (
        "enabling the first forwarded service no longer says what it is about to change about "
        "traffic it does not otherwise mention (ch4-9)")


@pytest.mark.proves("ch4-1", depth="integration")
def test_a_namespaced_service_is_not_covered_by_input_and_output():
    unwatched("ch4-1", "MEASURED 2026-08-17 and this records it rather than repeating it: three "
                       "namespaces, afirewall's real ruleset on the middle one, and a service "
                       "behind it. The package held five chains at `input`, two at `output`, one "
                       "at `prerouting` and NONE at `forward`, and a connection from outside "
                       "reached the service and was answered through a host whose posture is drop "
                       "in both directions. Automating the gap itself needs a ruleset built "
                       "WITHOUT this chapter's work, which no longer exists")
