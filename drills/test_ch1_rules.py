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

import os
import pathlib
import re
import subprocess
import sys

import pytest

from undrilled import unwatched

ROOT = pathlib.Path(__file__).resolve().parent.parent

# A rule carries a limit if it rate-limits or counts connections. Those are the rules that have a
# posture to argue; a plain `accept` has nothing to defend beyond the flag that selected it.
_HAS_LIMIT = re.compile(r"limit rate|ct count")

_POSTURE = re.compile(r"#\s*LIMIT POSTURE:\s*(?P<why>.+)", re.I)


def templates():
    """Every file that generates rules, INCLUDING base.rules.

    base.rules was outside this sweep in the first cut and that was wrong twice over: it carries
    thirty limit-bearing rules, and it is the only file in the package whose limits enforce by
    falling through rather than by saying `drop` — which is precisely the form a reader who has
    learned the `continue` idiom beside it will misread.
    """
    for family in ("ipv4", "ipv6"):
        base = ROOT / "templates" / family / "base.rules"
        if base.is_file():
            yield f"{family}/base.rules", base.read_text()
        for side in ("inbound", "outbound"):
            directory = ROOT / "templates" / family / side
            if directory.is_dir():
                for rules in sorted(directory.glob("*.rules")):
                    yield f"{family}/{side}/{rules.name}", rules.read_text()


def limit_verdicts(text):
    """What each limit-bearing rule actually does with a packet that exceeds it.

    READ FROM THE RULE'S OWN VERDICT, which is its last word, because nft gives a limit three
    endings and only two of them are obvious:

      `... } continue`  the packet falls to the unconditional accept below — INSTRUMENT
      `... over N } drop`  the packet is refused in as many words — ENFORCE
      `... limit rate N } accept`  the limit is a MATCH: over the rate the rule stops matching,
                                   nothing below accepts, and the chain policy drops — ENFORCE

    The first version of this recognised only the explicit `drop` and would have called every
    ICMP rule in base.rules an unfulfilled claim of enforcement. A drill that cannot see a third
    form reports the file rather than the fault.
    """
    verdicts = set()
    for line in text.splitlines():
        rule = line.strip()
        if rule.startswith("#") or not _HAS_LIMIT.search(rule):
            continue
        verdicts.add("instrument" if rule.split()[-1] == "continue" else "enforce")
    return verdicts


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
    unwatched("ch1-3", "a reader checking each recorded answer against how the service actually "
                       "behaves. The pass has been made and every limit now names its transport "
                       "and its collateral, but whether those answers are RIGHT is a review and "
                       "not something a test can take — a drill that searched the notes for the "
                       "word 'UDP' would pass on a note that said anything at all")


@pytest.mark.proves("ch1-4", depth="structural")
def test_an_instrumenting_limit_is_followed_by_an_accept():
    """The fail-open half, asserted so it cannot be half-removed. A `continue` limit whose accept
    was deleted would silently become a drop-everything rule — the limit does not admit anything by
    itself, it only declines to decide."""
    for name, text in templates():
        if "instrument" not in limit_verdicts(text):
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
                if limit_verdicts(text) and not _POSTURE.search(text)]
    assert not unargued, (
        f"{len(unargued)} template(s) carry a limit with no recorded argument for enforcing or "
        "instrumenting:\n  " + "\n  ".join(unargued)
        + "\nAdd a '# LIMIT POSTURE: <enforce|instrument> — <why>' note beside the rule.")

    # And a note that disagrees with its rule is worse than no note, because it is believed.
    #
    # ONE DRILL, NOT TWO, AND THE REASON IS THE DEPTH. Citing one subject twice is the normal
    # pattern here and is right — a structural half and a behavioural half say different things
    # about the same claim, and the board keeps them apart because they sit at different rungs.
    # Two citations at the SAME depth do not stay apart: they reduce to one status, a story drops
    # failing citations by design, and the passing one wins. So a subject with two structural
    # drills reads PROVEN off whichever holds while the other is red, and nothing on the board
    # says so — ansible's ch9-6 was green exactly that way with a flag that named nothing.
    # One depth, one drill; the ordering below then keeps the second half honest, because the
    # comparison only runs once the notes it compares are known to exist.
    noted = [name for name, text in templates() if _POSTURE.search(text)]
    assert noted, ("no template records a limit posture, so the comparison below would pass by "
                   "having nothing to compare")
    wrong = []
    for name, text in templates():
        verdicts = limit_verdicts(text)
        if not verdicts:
            continue
        if len(verdicts) > 1:
            wrong.append(f"{name}: some of its limits {sorted(verdicts)} — one note cannot "
                         "describe both, so either split the argument or make the rules agree")
            continue
        note = _POSTURE.search(text)
        head = note.group("why").lower().split("—")[0]
        claimed = "enforce" if "enforce" in head else "instrument"
        actual = verdicts.pop()
        if claimed != actual:
            wrong.append(f"{name}: the note says {claimed}, the rules {actual}")
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
    """`nft -c` against a fully rendered ruleset, which is the only check here that is not a guess
    about what nft wants.

    THIS WAS UNWATCHED AND SHOULD NOT HAVE BEEN. The reason recorded for not taking the reading was
    that nft is not installed — and nft was installed the whole time, at `/sbin/nft`, which is not
    on a non-root PATH. `shutil.which` returning nothing was read as absence, which is the same
    mistake as a search proving absence. Taking the reading immediately found `ip saddr` in an ip6
    template, and nft refuses a table containing one unloadable rule, so every host with
    `inbound.tcp8000` enabled would have had no IPv6 firewall at all.

    The observation delegates to the package's own suite rather than restating it: `-c` checks and
    never commits, and root is needed because nft parses first and only then reads the kernel's
    ruleset, so an unprivileged run stops at the syntax and proves nothing.
    """
    if os.geteuid() != 0:
        unwatched("ch1-7", "`nft -c` against a rendered ruleset, which needs root — nft parses "
                           "first and only then reads the kernel ruleset, so an unprivileged run "
                           "stops at the syntax. Run the board under sudo to take this reading")
    checked = subprocess.run(
        [sys.executable, "-m", "unittest",
         "test.test_afirewall.TestAfirewall.testNftAcceptsTheRenderedRuleset"],
        cwd=ROOT, capture_output=True, encoding="UTF-8")
    assert checked.returncode == 0, f"nft refuses the rendered ruleset:\n{checked.stderr}"


@pytest.mark.proves("ch1-8", depth="unit")
def test_every_rule_can_be_defended():
    unwatched("ch1-8", "a reader asking 'why does this rule do that?' of each template and finding "
                       "an answer they accept. ch1-6 now holds across the whole set, which makes "
                       "an answer PRESENT everywhere; that it is a good one is the judgement this "
                       "chapter exists to invite and cannot make on its own behalf")


@pytest.mark.proves("ch1-9", depth="structural")
def test_incoherent_traffic_is_dropped_before_any_flag_is_consulted():
    """The package's other reason to exist, asserted so it cannot be quietly lost.

    These four chains are what a host gets from installing afirewall at all — they run at
    `priority raw`, ahead of every service decision, and none of them reads the configuration. A
    flag cannot turn them off and a missing flag cannot bypass them, which is exactly why they are
    the part that does not need arguing per service.

    THE COUNTERS ARE PART OF THE CLAIM, not decoration. `nft list counters` says whether a rule has
    ever fired, so a drop rule that matches nothing is visible rather than assumed — which is the
    same standard this chapter holds a limit to.
    """
    for family in ("ipv4", "ipv6"):
        text = (ROOT / "templates" / family / "base.rules").read_text()
        for chain in ("SPOOFING", "INVALID_FLAGS", "PORT_ZERO"):
            assert f"chain {chain} {{" in text, (
                f"{family}/base.rules no longer defines {chain}. It runs ahead of every service "
                "decision and reads no flag, so losing it silently weakens every host that "
                "installs this package, whatever their configuration says")
        drops = [line.strip() for line in text.splitlines()
                 if line.strip().endswith("drop") and "counter name" in line]
        assert drops, (
            f"{family}/base.rules has no counted drops left, so nothing can say whether the "
            "sanity rules have ever fired — a rule that matches nothing looks identical to one "
            "that is working")
