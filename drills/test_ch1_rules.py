"""Chapter 1 drills — whether every rule this package generates can be defended.

The argument is in ``spec/diagrams/chapter-01-rules.md`` and is not repeated here.

These read the templates rather than a running host. Whether a limit set above a bounded legitimate
rate actually refuses abuse without refusing use is a claim about traffic (``ch1-U2``) and needs
load generated against it; what a drill can settle is that the posture was chosen and written down.

Note that ``test/test_afirewall.py`` already gates three-way skew — every conf key has a template,
every template has a key, every include resolves in its own family. Those are the package's own
tests and are not rdeploymentd here; this chapter is about the reasoning behind a rule rather than the
consistency of the set.
"""

import pathlib
import re

import pytest

from undrilled import unwatched

ROOT = pathlib.Path(__file__).resolve().parent.parent

# A template carries a limit if it rate-limits or counts connections. Those are the rules that have
# a posture to argue; a plain `accept` has nothing to defend beyond the flag that selected it.
_HAS_LIMIT = re.compile(r"limit rate|ct count")

# The two postures, read from the rule rather than from prose: `continue` hands the packet on to
# the accept below, `over ... drop` refuses it.
_INSTRUMENTS = re.compile(r"\bcontinue\b")
_ENFORCES = re.compile(r"over\s+\d+\s*(\}\s*)?drop|over\s+\S+\s+drop")

_POSTURE = re.compile(r"#\s*LIMIT POSTURE:\s*(?P<why>.+)", re.I)


def templates():
    for family in ("ipv4", "ipv6"):
        for side in ("inbound", "outbound"):
            directory = ROOT / "templates" / family / side
            if directory.is_dir():
                for rules in sorted(directory.glob("*.rules")):
                    yield f"{family}/{side}/{rules.name}", rules.read_text()


@pytest.mark.proves("ch1-1", depth="structural")
def test_both_directions_drop_by_default():
    """The posture the whole package rests on. If a blanket `ct state established,related accept`
    ever appears, an omitted flag stops being a dead service and starts being invisible — which is
    a weaker arrangement wearing the same name."""
    base = (ROOT / "templates/ipv4/base.rules").read_text()
    assert "hook input priority 20; policy drop" in base, "the input chain no longer drops"
    assert "hook output priority filter; policy drop" in base, "the output chain no longer drops"
    blanket = [ln.strip() for ln in base.splitlines()
               if "ct state" in ln and "established" in ln and "related" in ln and "{%" not in ln]
    assert not blanket, f"a blanket conntrack accept has appeared: {blanket}"


@pytest.mark.proves("ch1-2", depth="structural")
def test_the_config_stays_a_plain_list_of_flags():
    """Administrable through ansible is a constraint on THIS package. A fleet composes a host's
    ruleset by restoring this file and letting each service play add a line, so anything that made
    the format structured — a nested mapping, a list, a section header — would break the consumer
    however much cleaner it read."""
    conf = (ROOT / "afirewall.conf").read_text()
    for line in conf.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        assert re.fullmatch(r"(in|out)bound\.[a-z0-9]+:\s*(enable|disable)", line), (
            f"afirewall.conf carries a line ansible cannot compose by appending: {line!r}")


@pytest.mark.proves("ch1-3", depth="unit")
def test_spoofability_is_asked_of_the_service():
    unwatched("ch1-3", "the question asked of each service and its transport together — which is "
                       "ch1-U1, a pass over every template rather than a reading a test can take")


@pytest.mark.proves("ch1-4", depth="structural")
def test_an_instrumenting_limit_is_followed_by_an_accept():
    """The fail-open half, asserted so it cannot be half-removed. A `continue` limit whose accept
    was deleted would silently become a drop-everything rule — the limit does not admit anything by
    itself, it only declines to decide."""
    for name, text in templates():
        if not _HAS_LIMIT.search(text) or not _INSTRUMENTS.search(text):
            continue
        chain = text[text.index("chain "):] if "chain " in text else text
        assert re.search(r"\baccept\b", chain), (
            f"{name} instruments its limit with `continue` and never accepts, so the traffic it "
            "counts is dropped by the chain policy — the opposite of what instrumenting means")


@pytest.mark.proves("ch1-5", depth="unit")
def test_enforcing_needs_a_bounded_legitimate_rate():
    unwatched("ch1-5", "for each enforcing template, the legitimate rate its protocol produces, "
                       "measured rather than assumed, against the limit the rule sets — which is "
                       "ch1-U2 and needs traffic")


@pytest.mark.proves("ch1-6", depth="structural")
def test_every_limit_records_its_posture():
    """The claim that would have prevented both mistakes. Twelve templates were read as broken by
    one reader; others were rewritten to enforce by another who had no argument to read. An
    unexplained posture is indistinguishable from an accident, and both readers acted on that."""
    unargued = [name for name, text in templates()
                if _HAS_LIMIT.search(text) and not _POSTURE.search(text)]
    assert not unargued, (
        f"{len(unargued)} template(s) carry a limit with no recorded argument for enforcing or "
        "instrumenting:\n  " + "\n  ".join(unargued)
        + "\nAdd a '# LIMIT POSTURE: <enforce|instrument> — <why>' note beside the rule.")


@pytest.mark.proves("ch1-6", depth="structural")
def test_a_recorded_posture_matches_what_the_rule_does():
    """A note that disagrees with its rule is worse than no note, because it is believed.

    ASSERTS THE NOTES EXIST FIRST. Without that this passes by having nothing to compare, and the
    subject reads PROVEN off a vacuous check while its sibling drill is red — which is the
    inert-grounding trap, and exactly the shape of fault this whole spec is about.
    """
    noted = [name for name, text in templates() if _POSTURE.search(text)]
    assert noted, ("no template records a limit posture yet, so this drill would pass by having "
                   "nothing to check — it is only meaningful once ch1-6's other half is")
    wrong = []
    for name, text in templates():
        note = _POSTURE.search(text)
        if not note:
            continue
        says = note.group("why").lower()
        claims_enforce = "enforce" in says.split("—")[0].split("-")[0]
        if claims_enforce and not _ENFORCES.search(text):
            wrong.append(f"{name}: says enforce, no `over ... drop` in the rules")
        if not claims_enforce and _ENFORCES.search(text) and not _INSTRUMENTS.search(text):
            wrong.append(f"{name}: says instrument, but the rules drop")
    assert not wrong, "a recorded posture disagrees with its rule:\n  " + "\n  ".join(wrong)


@pytest.mark.proves("ch1-7", depth="structural")
def test_nothing_reaches_for_iptables():
    """Pure nft is a decision the operator already took — fwknop was rejected for depending on
    iptables, and fail2ban is pinned to the nft backend for the same reason.

    ASSERTED ON CODE AND NOT ON PROSE. The first version of this flagged three files and all three
    were reference URLs in comments — netfilter's own HOWTO among them. A drill that cannot tell a
    citation from a dependency produces exactly the kind of finding this repository spends its time
    disproving, so comments are stripped before the search.
    """
    reaching = []
    for path in sorted(ROOT.rglob("*")):
        if path.is_dir() or {".git", "__pycache__", "drills", "spec"} & set(path.parts):
            continue
        if path.suffix not in (".py", ".rules", ".conf", ".sh") and path.name != "afirewall":
            continue
        for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            code = line.split("#")[0]
            if re.search(r"(?<!nft)\biptables\b", code):
                reaching.append(f"{path.relative_to(ROOT)}:{number}")
    assert not reaching, f"iptables is used, which this package exists to leave: {reaching}"


@pytest.mark.proves("ch1-7", depth="integration")
def test_the_ruleset_loads_whole_or_not_at_all():
    unwatched("ch1-7", "`nft -c` against a generated ruleset as root — the package's own tests "
                       "already skipUnless(root) for exactly this, because nft parses first and "
                       "only then reads the kernel ruleset")


@pytest.mark.proves("ch1-8", depth="unit")
def test_every_rule_can_be_defended():
    unwatched("ch1-8", "a reader asking 'why does this rule do that?' of each template and finding "
                       "an answer — which is ch1-6 holding across the whole set rather than a "
                       "separate observation")
