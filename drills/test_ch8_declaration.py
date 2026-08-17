"""Chapter 8 drills — whether a service really is declared once.

The argument is in ``spec/diagrams/chapter-08-declaration.md``.

**THESE ASK THE RESOLVER, NOT THE FILES.** The fault this chapter exists for was four hand-typed
copies of a name that nothing compared, and a drill that read `base.rules` looking for them would be
the same shape as the mistake. What is asserted instead is the property: a declared service, when
switched on, produces a chain, a jump and a reply — in both families — or it does not exist.
"""

import os
import pathlib
import subprocess
import sys

import pytest

from undrilled import unwatched

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from afirewall import afirewall  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
FAMILIES = ("ipv4", "ipv6")


def catalogue():
    return afirewall.load_catalogue(str(ROOT))


def bodies(family, direction, name):
    """One service, switched on alone, as the renderer hands it to base.rules."""
    config = {"inbound": {}, "outbound": {}}
    config[direction][name] = True
    return afirewall.service_bodies(str(ROOT), family, config)[direction]


@pytest.mark.proves("ch8-2", depth="structural")
def test_a_service_is_one_record_that_says_everything_about_it():
    """A record with no way to select traffic is a switch wired to nothing, which is the fault
    this chapter is named after arriving in the new file instead of the old one."""
    records = catalogue()
    assert records, "services.toml declares nothing, so no service can be reached at all"
    for (direction, name), record in sorted(records.items()):
        assert direction in ("inbound", "outbound"), f"{name} has direction {direction!r}"
        assert record["name"] == name and record["direction"] == direction, (
            f"{direction}.{name}'s record disagrees with its own key, so the catalogue has two "
            "names for one service — which is the shape of every fault this chapter removes")
        assert record.get("ports") or record.get("selector"), (
            f"{direction}.{name} selects no traffic: it has neither ports nor a selector, so it "
            "renders a chain nothing reaches")


@pytest.mark.proves("ch8-3", depth="structural")
def test_base_rules_names_no_service():
    """The mechanism, asserted directly. While `base.rules` names services one line at a time,
    adding one means editing it — which is ch2-U4 — and the name exists in four places, which is
    how two of them came to be misspelt."""
    for family in FAMILIES:
        text = (ROOT / "templates" / family / "base.rules").read_text()
        for (direction, name) in catalogue():
            assert f"{direction}.{name}" not in text, (
                f"{family}/base.rules names {direction}.{name}. Services are reached through their "
                "records now; a name written here is a second place for it to be wrong")


@pytest.mark.proves("ch8-4", depth="structural")
def test_every_service_gets_a_chain_a_jump_and_a_reply_in_both_families():
    """THE ONE THAT WOULD HAVE CAUGHT ALL THREE. Before this chapter a service needed four lines
    typed by hand and nothing compared them, so `inbound.tcp2194`'s reply was guarded by
    `inbound.tcp2914`, `inbound.tcp8000` had no reply at all, and `outbound.udp1514` had no jump —
    three services shipped dead or half-dead, and every test the package had passed.

    A service that accepts a connection it cannot answer is not a narrower service, it is a broken
    one: both directions default to drop with no blanket established accept (`ch1-1`), so the reply
    dies on the output policy.
    """
    for (direction, name) in sorted(catalogue()):
        for family in FAMILIES:
            found = [s for s in bodies(family, direction, name) if s["name"] == name]
            assert found, f"{direction}.{name} is declared and renders nothing in {family}"
            service = found[0]
            assert service["jumps"], (
                f"{family} {direction}.{name} has no jump, so its chain is rendered and never "
                "reached — which is what outbound.udp1514 was")
            assert service["replies"], (
                f"{family} {direction}.{name} has no reply, so it can accept a connection and "
                "never answer it — which is what inbound.tcp2194 and inbound.tcp8000 were")
            assert service["include"] or f"chain ACCEPT_{name.upper()}" in service["body"], (
                f"{family} {direction}.{name} renders no chain for its jump to land on")


@pytest.mark.proves("ch8-5", depth="structural")
def test_a_limit_still_carries_the_argument_for_itself():
    """ch1-6 survives the move. What changed is where the prose is stored, not whether it exists
    or where a reader finds it — it still lands inside the chain in the rendered ruleset."""
    for (direction, name), record in sorted(catalogue().items()):
        if not record.get("posture"):
            continue
        assert record.get("because", "").strip(), (
            f"{direction}.{name} has a posture and no argument for it, which is exactly the state "
            "ch1-U1 needed a sweep over 36 files to fix")
        for field in ("rate", "count"):
            assert record.get(field) is not None, (
                f"{direction}.{name} is {record['posture']} and states no {field}")
        for family in FAMILIES:
            service = [s for s in bodies(family, direction, name) if s["name"] == name][0]
            if service["include"]:
                continue
            assert "LIMIT POSTURE: " + record["posture"] in service["body"], (
                f"{family} {direction}.{name} renders no posture note, so the rule arrives in the "
                "ruleset with nobody's argument attached")


@pytest.mark.proves("ch8-7", depth="structural")
def test_a_hand_written_template_wins_and_is_still_claimed_by_a_record():
    """The escape hatch, from both sides. A template must be reached — which means a record has to
    name its service — and where one exists it must be what renders, not the record's body."""
    for family in FAMILIES:
        for direction in ("inbound", "outbound"):
            directory = ROOT / "templates" / family / direction
            if not directory.is_dir():
                continue
            for template in sorted(directory.glob("*.rules")):
                name = template.stem
                assert (direction, name) in catalogue(), (
                    f"{template} has no record, so nothing will ever open it")
                service = [s for s in bodies(family, direction, name) if s["name"] == name][0]
                assert service["include"] == f"{family}/{direction}/{name}.rules", (
                    f"{direction}.{name} has a hand-written template and the renderer is not using "
                    "it, so an operator's override is being silently ignored")
                assert service["body"] is None, (
                    f"{direction}.{name} rendered a body AND has a template — two rule sets for "
                    "one service, and nothing says which the kernel got")


@pytest.mark.proves("ch8-9", depth="structural")
def test_a_local_record_overrides_one_service_and_adopts_nothing(tmp_path, monkeypatch):
    """Merged, not replaced. A base directory that replaced the catalogue would rebuild ch2-U4 one
    file along: a stranger adding one service would adopt the whole list and stop receiving every
    upstream addition to it.

    SHIPPED is pointed at this checkout for the duration, because on a development machine there is
    no /usr/share/afirewall — and a merge test that silently had nothing to merge would pass while
    proving nothing, which is the failure this whole chapter came out of.
    """
    monkeypatch.setattr(afirewall, "SHIPPED", str(ROOT))
    (tmp_path / "services.toml").write_text(
        '[[service]]\nname = "ssh"\ndirection = "inbound"\nports = ["tcp/2222"]\n'
        '\n[[service]]\nname = "gemini"\ndirection = "inbound"\nports = ["tcp/1965"]\n')
    merged = afirewall.load_catalogue(str(tmp_path))
    assert ("inbound", "gemini") in merged, "a local record did not arrive"
    assert merged[("inbound", "ssh")]["ports"] == ["tcp/2222"], (
        "a local record did not override the shipped one it names")
    shipped = catalogue()
    missing = set(shipped) - set(merged)
    assert not missing, (
        f"a local catalogue replaced the shipped one instead of merging over it, losing "
        f"{len(missing)} service(s): {sorted(missing)[:5]}")


@pytest.mark.proves("ch8-8", depth="integration")
def test_the_ruleset_is_the_one_this_host_rendered_before():
    unwatched("ch8-8", "the migration's own diff, which was taken once and cannot be taken again "
                       "now the templates it compared against are deleted. MEASURED 2026-08-17, "
                       "every flag enabled, both families: ZERO rules lost and four gained per "
                       "family — the replies inbound.tcp2194 and inbound.tcp8000 never had, and "
                       "the jump and reply outbound.udp1514 never had. 18 posture notes, 34 set "
                       "declarations and 41 chains in each family before and after, and every "
                       "argument's text still present. What a drill can carry forward is the "
                       "property rather than the diff, which is the test above")


@pytest.mark.proves("ch8-10", depth="unit")
def test_the_rendering_path_is_no_longer_readable_one_file_at_a_time():
    unwatched("ch8-10", "a reader who does not know this package being asked what postgres does, "
                        "and finding out. It is a bad ending taken deliberately and the only "
                        "honest instrument for it is somebody unfamiliar reading the tree")


@pytest.mark.proves("ch8-11", depth="structural")
def test_the_questions_about_files_agreeing_are_gone():
    """Success is the tests that stop being necessary. Three-way skew — a key, a template and the
    wiring — is now a two-way question the catalogue answers, and ch8-U2 is the half that is left.
    """
    for family in FAMILIES:
        directory = ROOT / "templates" / family
        service_templates = list((directory / "inbound").glob("*.rules")) if \
            (directory / "inbound").is_dir() else []
        service_templates += list((directory / "outbound").glob("*.rules")) if \
            (directory / "outbound").is_dir() else []
        assert len(service_templates) <= 2, (
            f"{family} carries {len(service_templates)} service templates. The escape hatch is for "
            "shapes a record cannot say (ch8-6), and a rising count means the record format is "
            "failing to cover the common case rather than that the hatch is popular")
