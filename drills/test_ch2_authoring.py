"""Chapter 2 drills — whether somebody can add a service without learning the template layout.

The argument is in ``spec/diagrams/chapter-02-authoring.md`` and is not repeated here.

**THESE ARE RED AND THAT IS THE POINT.** Nothing here has been built yet, so every drill below
fails naming what is missing. That is the honest reading rather than a gap to soften: a chapter
whose claims are all unproven *is* the work item, and a drill marked unwatched would say the
opposite — unwatched means nobody has taken a reading, not that there is nothing to read.

They are structural because what they check is shape — does the tool exist, does it refuse a
missing argument, does it write both families — and shape is settled by reading. The behavioural
half, that a generated template actually loads into a kernel, belongs to ``ch1-7`` and needs root.
"""

import pathlib
import re

import pytest

from undrilled import unwatched

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The generator's home is not decided (``ch2-U1``) — a subcommand of ``afirewall`` and a separate
#: authoring tool are both defensible. So this looks for the capability rather than for a filename,
#: and any of these being true satisfies it.
CANDIDATES = ("afirewall/authoring.py", "afirewall/add_service.py", "afirewall/afirewall.py")


def authoring():
    """The authoring implementation, or a failure that says what is absent.

    NAMES WHAT IS MISSING RATHER THAN SKIPPING. A skip here would read as 'not observed' on the
    board, which is wrong twice: the observation is trivial to take, and what it would find is that
    the feature does not exist. That is evidence, not an absence of it.
    """
    for relative in CANDIDATES:
        path = ROOT / relative
        if not path.is_file():
            continue
        text = path.read_text()
        if re.search(r"add[-_ ]?service|authoring|render_template", text, re.I):
            return text
    pytest.fail(
        "nothing in this package can author a template. A person whose service has no flag has to "
        "hand-write whitespace-sensitive Jinja, run the service unprotected, or stop using the "
        f"package. Looked in: {', '.join(CANDIDATES)}")


@pytest.mark.proves("ch2-1", depth="unit")
def test_the_coverage_gap_is_measured():
    unwatched("ch2-1", "what services people actually fail to find a flag for — which is ch2-U3. "
                       "The two gaps named in the chapter are this deployment's own and are a sample "
                       "of one, and whether the missing templates are mostly databases or mostly "
                       "things nobody would guess decides whether a generator is the whole answer")


@pytest.mark.proves("ch2-2", depth="structural")
def test_a_service_is_named_rather_than_a_bare_port():
    """The claim that keeps ch1-6 writable. A rule for `tcp/9999` has no counterparty, so no
    posture can be argued for it; the name is what the argument attaches to."""
    text = authoring()
    assert re.search(r"\bname\b", text), (
        "the authoring path does not take a service name, so what it writes cannot carry an "
        "argument about who is refused when its limit bites")


@pytest.mark.proves("ch2-3", depth="structural")
def test_one_name_carries_more_than_one_protocol_and_port():
    """A forwarding host wants udp and tcp on the same number and bacula uses three ports across three
    roles. A tool that takes one port makes the common awkward case unreachable."""
    text = authoring()
    assert re.search(r"ports\b|nargs\s*=\s*['\"][+*]['\"]|append", text), (
        "the authoring path looks like it takes a single protocol/port, so a service that is more "
        "than one — a forwarding host on udp and tcp, a port range — has no way to be expressed")


@pytest.mark.proves("ch2-4", depth="structural")
def test_the_posture_and_its_reason_are_required_arguments():
    """The reason this chapter is worth building rather than a convenience. ch1-6 is aspirational
    while an unargued rule is writable; it becomes structural the moment it is not."""
    text = authoring()
    assert re.search(r"posture", text, re.I), (
        "the authoring path never asks for a limit posture, so it can write exactly the unargued "
        "rules ch1-6 exists to prevent — at speed, which is worse than by hand")
    assert re.search(r"required\s*=\s*True|because|reason", text, re.I), (
        "a posture can be given without a reason, so the tool would record a verdict nobody "
        "argued — which is the state ch1-U1 had to sweep 36 files to fix")


@pytest.mark.proves("ch2-5", depth="structural")
def test_there_is_no_default_posture():
    """Refusing is the feature. A default would manufacture, at scale, the exact ambiguity that
    got twelve templates read as broken and several others rewritten without a case being made."""
    text = authoring()
    offenders = [line.strip() for line in text.splitlines()
                 if re.search(r"posture", line, re.I) and re.search(r"default\s*=", line)]
    assert not offenders, (
        "the authoring path has a default posture, so a rule can be written without anybody "
        f"choosing one: {offenders}")


@pytest.mark.proves("ch2-6", depth="structural")
def test_both_families_are_written_or_neither_is():
    """The IPv6 ruleset in this package went years without loading because ipv4 assumptions were
    copied into it. A tool that made v4 easy and v6 optional would rebuild that on purpose."""
    text = authoring()
    assert "ipv6" in text.lower() and "ipv4" in text.lower(), (
        "the authoring path does not write both families, so a generated service is an IPv4 "
        "service wearing a neutral name — which is how the v6 ruleset broke the first time")


@pytest.mark.proves("ch2-7", depth="structural")
def test_a_generated_template_is_not_marked_as_generated():
    """No second class of template. A registry of generated services, or a marker distinguishing
    them, is a second thing to keep true and the package already has three-way skew checks."""
    text = authoring()
    offenders = [line.strip() for line in text.splitlines()
                 if re.search(r"DO NOT EDIT|autogenerated|auto-generated|generated by", line, re.I)]
    assert not offenders, (
        "the authoring path marks its output as generated, which makes it a second class of "
        f"template with its own maintenance path: {offenders}")


@pytest.mark.proves("ch2-8", depth="integration")
def test_a_stranger_covers_a_service_the_package_never_shipped():
    unwatched("ch2-8", "somebody who did not write this package adding a service with the tool and "
                       "the rule working — the measure is a person's experience and cannot be "
                       "taken from inside the repository")
