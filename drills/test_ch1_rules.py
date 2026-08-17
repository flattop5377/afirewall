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
import shutil
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
    """Administrable through ansible is a constraint on THIS package. A configurator composes a host's
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
    # says so — a consumer's board read green exactly that way with a flag that named nothing.
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
    """Pure nft is a decision this package already took — fwknop was rejected for depending on
    iptables, and fail2ban is pinned to the nft backend for the same reason.

    ASSERTED ON CODE AND NOT ON PROSE. The first version of this flagged three files and all three
    were reference URLs in comments — netfilter's own HOWTO among them. A drill that cannot tell a
    citation from a dependency produces exactly the kind of finding this repository spends its time
    disproving, so comments are stripped before the search.
    """
    NOT_THE_PACKAGE = {".git", "__pycache__", "drills", "spec", ".venv"}
    # `.venv` IS SOMEBODY'S SITE-PACKAGES AND NOT THIS PACKAGE. The README tells a developer to
    # create it right here, so this drill was always one `pip install` away from reporting a
    # dependency's source as afirewall reaching for iptables — and on 2026-08-17 adding scapy did
    # exactly that. What it found was a library's comment-free mention of a tool this package does
    # not call, which is the same false finding the docstring above records having fixed once.
    reaching = []
    for path in sorted(ROOT.rglob("*")):
        if path.is_dir() or NOT_THE_PACKAGE & set(path.parts):
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


# nftables' named priorities, and the two kernel hooks that decide whether a sanity chain is
# reachable at all. `raw` is ahead of conntrack; DEFRAG is ahead of `raw` and is where a fragment
# stops being a fragment.
_RAW = -300
_CONNTRACK = -200
_DEFRAG = -400
_NAMED = {"raw": _RAW, "mangle": -150, "dstnat": -100, "filter": 0, "srcnat": 100}

# `chain NAME {` and then the `type ... hook ... priority ...;` line that follows it.
_CHAIN = re.compile(r"chain (\w+) \{\s*\n\s*type \w+ hook (\w+) priority (-?\w+);")


def _base_chains(family: str) -> dict:
    """chain name -> (hook, numeric priority), from the INBOUND table of a family's base.rules.

    Scoped to that table deliberately: `INVALID_FLAGS` is defined in both, on `input` here and on
    `output` next door, so reading the whole file returns the outbound one and an assertion about
    the sanity chains silently asks about the wrong chain.
    """
    text = (ROOT / "templates" / family / "base.rules").read_text()
    # SPLIT ON THE TABLE'S DECLARATION, not on its name appearing anywhere. The file opens by
    # naming every table it is about to replace, so `-outbound-` now occurs above the inbound
    # table and splitting on the bare string cut the whole thing away - a drill that went red
    # because a preamble was added above what it reads.
    inbound = re.split(r"table ip6? a-firewall-outbound-\w+ \{", text)[0]
    return {name: (hook, _NAMED.get(prio, int(prio) if _is_int(prio) else prio))
            for name, hook, prio in _CHAIN.findall(inbound)}


def _is_int(value: str) -> bool:
    try:
        int(value)
        return True
    except ValueError:
        return False


# WHAT EACH SANITY CHAIN MUST BE, and the priority is half of it. A chain at the wrong priority is
# not a weaker rule, it is an absent one, and it looks identical from the template.
_SANITY = {
    "SPOOFING": ("input", _RAW),
    "INVALID_FLAGS": ("input", _RAW),
    "PORT_ZERO": ("input", _RAW),
    "FRAGMENTS": ("prerouting", -450),
}


@pytest.mark.proves("ch1-9", depth="structural")
def test_incoherent_traffic_is_dropped_before_any_flag_is_consulted():
    """The package's other reason to exist, asserted so it cannot be quietly lost.

    These four chains are what a host gets from installing afirewall at all — they run ahead of
    every service decision, in both families, and none of them reads the configuration. A flag
    cannot turn them off and a missing flag cannot bypass them, which is exactly why they are the
    part that does not need arguing per service.

    THE PRIORITY IS ASSERTED, AND IT IS WHY THIS DRILL WAS REWRITTEN. It used to check that a
    chain was *defined* and that *some* counted drop existed, while its own docstring said the
    chains run at `priority raw`. Three things were true underneath it and it read green through
    all of them: ipv6 SPOOFING was at `mangle` from the genesis commit, ipv6 had no FRAGMENTS
    chain at all, and the ipv4 FRAGMENTS chain was behind `nf_defrag` and could never fire. It
    also looped over three chains while the claim named four, which is how the missing one stayed
    missing.

    THE COUNTERS ARE PART OF THE CLAIM, not decoration. `nft list counters` says whether a rule has
    ever fired, so a drop rule that matches nothing is visible rather than assumed — which is the
    same standard this chapter holds a limit to. That only means anything if the chain is somewhere
    a packet still reaches it, which is what the priority assertions below are for.
    """
    for family in ("ipv4", "ipv6"):
        found = _base_chains(family)
        for chain, (hook, priority) in _SANITY.items():
            assert chain in found, (
                f"{family}/base.rules does not define {chain}. It runs ahead of every service "
                "decision and reads no flag, so losing it silently weakens every host that "
                "installs this package, whatever their configuration says. Both families get all "
                f"four: ipv6 went without {chain} once, on the reasoning that IPv6 removed "
                "something it did not remove")
            assert found[chain] == (hook, priority), (
                f"{family} {chain} is at {found[chain]}, not {(hook, priority)}. A sanity chain at "
                "the wrong priority is an absent one that reads present: at `mangle` it runs "
                "behind conntrack and the packet it drops has already been tracked, and behind "
                "DEFRAG it is handed a reassembled datagram with no fragment left to match")

        assert found["FRAGMENTS"][1] < _DEFRAG, (
            f"{family} FRAGMENTS is at {found['FRAGMENTS'][1]}, which is behind nf_defrag at "
            f"{_DEFRAG}. Every host running these templates asks for conntrack, so defrag is "
            "registered and reassembly has already happened — the rule cannot match, its counter "
            "can only read zero, and a zero is indistinguishable from 'no fragments arrived'")

        text = (ROOT / "templates" / family / "base.rules").read_text()
        drops = [line.strip() for line in text.splitlines()
                 if line.strip().endswith("drop") and "counter name" in line]
        assert drops, (
            f"{family}/base.rules has no counted drops left, so nothing can say whether the "
            "sanity rules have ever fired — a rule that matches nothing looks identical to one "
            "that is working")


SOURCE = (ROOT / "afirewall" / "afirewall.py").read_text()


@pytest.mark.proves("ch1-10", depth="structural")
def test_the_generated_ruleset_outlives_a_reboot():
    """Where the rules are written decides whether a host boots with a firewall.

    They were in /run, which tmpfs empties at every boot, so `start` had nothing to restore and
    rebuilt — at the one moment a rebuild cannot work, because netfilter-persistent runs this
    plugin before the network is configured and the interface is discovered by routing lookup.
    Measured on a host, 2026-08-16: no interface found, nothing generated, tables deleted anyway,
    exit 0.
    """
    found = re.search(r"^GENERATED\s*=\s*'([^']+)'", SOURCE, re.M)
    assert found, "GENERATED is no longer a plain assignment, so nothing here can say where it points"
    where = found.group(1)
    assert not where.startswith(("/run", "/tmp", "/var/run")), (
        f"generated rules are written to {where}, which does not survive a reboot. `start` will "
        "find nothing to restore and rebuild instead, and at boot there is no route to discover an "
        "interface by — so the host comes up with no firewall at all.")


@pytest.mark.proves("ch1-10", depth="structural")
def test_the_boot_verb_restores_and_never_rebuilds():
    """The verb netfilter-persistent sends at boot must not be one that needs the network.

    netfilter-persistent runs its plugins with `run-parts -a <verb>` and sends only `start`, `save`
    and `flush` — its own `reload` and `restart` both call the plugin with `start`. So `start` is
    what arrives at boot AND what `systemctl restart netfilter-persistent` produces, and there is no
    verb it can send that means rebuild. It is aliased to `restore` here because a start that does
    not start reads as a mistake otherwise.

    It must not generate even as a fallback. A verb that usually restores and occasionally rebuilds
    behaves according to state the caller cannot see, which is the shape of the fault this subject
    exists because of.
    """
    cases = re.findall(r"^\s*case ([^:]+):\n((?:(?!^\s*case ).*\n)*)", SOURCE, re.M)
    bodies = {label.strip(): body for label, body in cases}
    restore = next((b for lbl, b in bodies.items() if "'start'" in lbl), None)
    assert restore is not None, "no case handles 'start', which is the verb netfilter-persistent sends"
    assert "'restore'" in next(lbl for lbl in bodies if "'start'" in lbl), (
        "'start' is not aliased to 'restore'. The ABI name has to stay, but a start that does not "
        "start needs the honest name beside it or the next reader corrects the wrong thing.")
    assert "generate()" not in restore, (
        "the boot verb generates. At boot there is no network, so generation finds no interface "
        "and the host is left bare — restoring the saved ruleset is the only thing that can work.")
    rebuild = next((b for lbl, b in bodies.items() if "'regenerate'" in lbl), None)
    assert rebuild is not None and "generate()" in rebuild, (
        "nothing regenerates, so a configuration change would never reach the kernel and a saved "
        "ruleset naming an old address would never be corrected")


@pytest.mark.proves("ch1-10", depth="structural")
def test_a_run_that_cannot_build_a_ruleset_changes_nothing():
    """The worst outcome available, and it was the one on offer.

    An empty interface list generated nothing, `stop()` deleted the four tables anyway, the glob
    found nothing to load, and the program exited 0. A host that had a firewall a moment earlier had
    none, and systemd recorded success. The only safe thing to do with a ruleset you cannot replace
    is leave it alone.
    """
    generate = re.search(r"def generate\(\):\n((?:(?! {3}def ).*\n)*)", SOURCE)
    assert generate, "generate() is gone, so nothing here can say what happens when it finds nothing"
    body = generate.group(1)
    guard = re.search(r"if not interfaces:\n\s*sys\.exit\(", body)
    assert guard, (
        "generate() no longer refuses when no interface is found in any family. Without that it "
        "returns having produced nothing, the caller deletes the loaded tables, and the run exits "
        "successfully with the host unprotected.")
    # MATCHED ON THE CALL, NOT ON ITS ARGUMENTS. This pinned the literal `test(args.basedir` and
    # broke the day `test` took the nft path as a parameter — a red drill about a signature, for a
    # claim that is entirely about ORDER: the refusal has to come before anything is generated.
    rendered = re.search(r"\btest\(", body)
    assert rendered and body.index("if not interfaces:") < rendered.start(), (
        "the refusal must come before anything is generated or torn down")


@pytest.mark.proves("ch1-10", depth="integration")
def test_a_rebooted_host_comes_up_with_its_firewall():
    unwatched("ch1-10", "a host rebooted and its tables read back from the kernel afterwards — "
                        "the three drills above inspect the source and cannot execute it, because "
                        "every command but add-service requires root, so what they settle is the "
                        "shape rather than the behaviour. DONE BY HAND on a host, 2026-08-16: before "
                        "the change the boot logged `no IPV4 interface found`, `Result=success` "
                        "and held no tables; after it the boot logged `Loading rules from "
                        "/var/lib/afirewall/ipv4.nft` and all four tables were present, with "
                        "wireguard, the alerter, apt and syslog all working through them. "
                        "Automating it needs the a host fixture this repository keeps deferring")


LAB = ROOT / "tools" / "lab.py"


@pytest.mark.proves("ch1-11", depth="integration")
@pytest.mark.proves("ch4-7", depth="integration")
def test_every_counter_moves_for_the_traffic_that_names_it():
    """The counters, read against traffic sent on purpose rather than against whatever arrived.

    THIS IS THE DRILL `ch1-9` NEEDED AND DID NOT HAVE. Everything above it reads templates, so it
    settles the shape of a rule and never whether the rule matches anything. That gap is what let
    three defects live under a PROVEN claim until 2026-08-17: a chain behind conntrack, a chain
    that did not exist in one family, and a chain behind `nf_defrag` whose counter could not move.

    It runs the real program against the working tree's templates inside a network namespace, so
    what is under test is this checkout rather than whatever package the machine has installed.
    Skipping without root is honest — the lab creates namespaces and loads a ruleset, and neither
    is available to a normal user. A skip here means nobody has shown the counters fire, which is
    the same thing `ch1-9` says about a counter that reads zero.

    IT ALSO CARRIES ch4-7, because the lab grew a third namespace and the same run now asks whether
    a service behind the target is reachable through it. Two claims off one run rather than two
    runs: the lab is expensive, and a second invocation would be the same evidence spent twice.
    """
    if os.geteuid() != 0:
        pytest.skip("the lab creates network namespaces and loads a ruleset — run the suite as "
                    "root, or `sudo python3 tools/lab.py` on its own")
    if not shutil.which("nft"):
        pytest.skip("nft is not on PATH, so no ruleset can be loaded to fire anything at")

    done = subprocess.run([sys.executable, str(LAB)], capture_output=True, text=True, timeout=300)
    # 2 IS "THIS MACHINE CANNOT ASK", WHICH IS A SKIP AND NOT A RED. Under `plumb board` this runs
    # from the repository's .venv, which carries jinja2 and no scapy — so the first version sent
    # nothing, read eight zero counters and reported eight broken rules against a firewall that
    # was working. The exit code is what keeps a harness fault from being read as a finding.
    if done.returncode == 2:
        pytest.skip(done.stderr.strip())
    assert done.returncode == 0, (
        "a sanity chain did not count the traffic that names it. Every packet on that wire was "
        f"sent by the lab, so a counter that did not move is the rule's fault:\n{done.stdout}\n"
        f"{done.stderr}")
