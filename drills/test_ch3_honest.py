"""Chapter 3 drills — whether the package tells the truth to whatever configures it.

The argument is in ``spec/diagrams/chapter-03-honest-to-its-configurator.md``.

**RED, AND NOT UNWATCHED.** None of this is built. A drill marked unwatched would say nobody has
taken a reading; what is true is that the reading is trivial and finds the feature absent, which is
evidence rather than the lack of it.
"""

import json
import pathlib
import re
import subprocess
import sys

import pytest

from undrilled import unwatched

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAIN = ROOT / "afirewall" / "afirewall.py"


def run(*arguments):
    """The command as a configurator would call it, against a copy of this tree rather than /etc."""
    return subprocess.run([sys.executable, str(MAIN), *arguments, "-b", str(ROOT)],
                          capture_output=True, encoding="UTF-8")


def subcommands():
    match = re.search(r"'command',\s*choices=\[(?P<list>[^\]]*)\]", MAIN.read_text())
    assert match, "afirewall's subcommand list has moved and this drill cannot find it"
    return set(re.findall(r"'([^']+)'", match.group("list")))


@pytest.mark.proves("ch3-1", depth="unit")
def test_a_configuration_manager_can_drive_this():
    unwatched("ch3-1", "somebody provisioning a host with a config manager that is not ansible — "
                       "the claim is that the interface serves any of them, and one consumer "
                       "existing does not settle it")


@pytest.mark.proves("ch3-2", depth="structural")
def test_a_flag_is_set_by_a_subcommand_that_can_refuse_it():
    """`lineinfile` will write anything, which is how `inbound.tor` survived years of successful
    converges while opening nothing. A command knows which keys have templates behind them."""
    have = subcommands()
    missing = {"enable", "disable"} - have
    assert not missing, (
        f"afirewall has no {sorted(missing)} subcommand, so a configurator can only edit the file "
        "as text — and text editing cannot refuse a flag that names no template. That is what "
        f"`inbound.tor` was. Present subcommands: {sorted(have)}")
    refused = run("enable", "inbound.nosuchservice")
    assert refused.returncode != 0, (
        "enabling a flag afirewall has no template for succeeded. The line will persist, survive "
        "every reload and open nothing, which is worse than a missing rule because it is invisible")


@pytest.mark.proves("ch3-3", depth="structural")
def test_it_can_be_asked_without_being_told():
    """A config manager asks before it acts. This deployment has already had a play read a fabricated
    success out of check mode and conclude an LVM volume existed on a host with no LVM."""
    assert "--dry-run" in MAIN.read_text(), (
        "there is no dry run, so a configurator's check mode can only pretend — and a `command:` "
        "under ansible's --check returns rc 0 with empty stdout rather than an undefined register, "
        "so the pretence reads as success")


@pytest.mark.proves("ch3-4", depth="structural")
def test_a_dry_run_still_refuses_what_a_real_run_would():
    """A dry run that skips validation reports success for a change that would have failed, which
    is worse than offering no dry run at all."""
    if "enable" not in subcommands():
        pytest.fail("no enable subcommand to dry-run")
    asked = run("enable", "inbound.nosuchservice", "--dry-run")
    assert asked.returncode != 0, "a dry run accepted a flag a real run would refuse"


@pytest.mark.proves("ch3-5", depth="structural")
def test_a_no_op_is_reported_as_a_no_op():
    """The signal fifteen plays gate their `afirewall reload` on. Without it every converge reloads
    the firewall on every host and a quiet run stops existing."""
    if "enable" not in subcommands():
        pytest.fail("no enable subcommand")
    first = run("enable", "inbound.ssh", "--dry-run")
    assert first.returncode == 0, f"enabling an existing flag failed: {first.stderr}"
    assert json.loads(first.stdout)["changed"] is False, (
        "enabling a flag that is already enabled reports a change, so a converged host would "
        "never be quiet")


@pytest.mark.proves("ch3-5", depth="structural")
def test_exit_status_means_success_and_nothing_else():
    """An exit code that meant *changed* would break `afirewall enable x && …` for every human at
    a shell, to save a configurator one parse."""
    if "enable" not in subcommands():
        pytest.fail("no enable subcommand")
    unchanged = run("enable", "inbound.ssh", "--dry-run")
    assert unchanged.returncode == 0, (
        "a no-op exits non-zero, so `afirewall enable x && ...` fails on a host that is already "
        "configured — changed is reported in the output, not in the exit status")


@pytest.mark.proves("ch3-6", depth="structural")
def test_what_it_reports_cannot_be_misread():
    """ONE JSON OBJECT, and the reason is a specific trap. The cheap answer is to print `changed`
    or `unchanged` and match on it — and `"changed" in stdout` is TRUE for `unchanged`, so every
    no-op reads as a change and the quiet run is lost anyway."""
    if "enable" not in subcommands():
        pytest.fail("no enable subcommand")
    reported = run("enable", "inbound.ssh", "--dry-run")
    payload = json.loads(reported.stdout)
    for key in ("changed", "flag", "was", "now"):
        assert key in payload, (
            f"the report has no {key!r}. A bare word cannot say which flag, or what it was — and "
            f"a caller matching on a substring cannot tell `changed` from `unchanged`: {payload}")


@pytest.mark.proves("ch3-7", depth="integration")
def test_a_converged_host_is_quiet():
    unwatched("ch3-7", "a fleet converge run twice, with the second run reporting no change on any "
                       "host — which is ch3-U3 and cannot be taken until a play is in the "
                       "converge at all (ansible ch9-11)")
