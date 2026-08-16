"""Chapter 7 drills — where the package puts things, and what an upgrade may change.

The argument is in ``spec/diagrams/chapter-07-layout.md``.

**THESE READ THE PACKAGING BRANCH.** What a package installs is stated in `debian/afirewall.install`
on `debian/latest`, not on master, so these ask git for it — the same way chapter 5's drills do.
They skip rather than fail when that branch is absent, because a partial checkout is not evidence.
"""

import pathlib
import re
import subprocess

import pytest

from undrilled import unwatched

ROOT = pathlib.Path(__file__).resolve().parent.parent


def git(*args):
    done = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, encoding="UTF-8")
    return done.stdout, done.returncode


def packaging(path):
    out, code = git("show", f"debian/latest:{path}")
    if code != 0:
        pytest.skip(f"debian/latest:{path} is not in this checkout")
    return out


@pytest.mark.proves("ch7-1", depth="structural")
def test_what_is_already_right_stays_right():
    """Stated so the fix cannot disturb it. The binary is administrative and belongs in /usr/sbin;
    the plugin path is the one thing that makes this package persist without a unit of its own."""
    install = packaging("debian/afirewall.install")
    links = packaging("debian/afirewall.links")
    assert re.search(r"afirewall/afirewall\.py\s*=>\s*/?usr/sbin/afirewall", install), (
        "the command is no longer installed to /usr/sbin, which is where an administrative binary "
        "belongs and where the netfilter-persistent plugin symlink points")
    assert "usr/share/netfilter-persistent/plugins.d/afirewall" in links, (
        "the netfilter-persistent plugin link is gone, so nothing restores the ruleset at boot")
    assert "doc/man/afirewall.8" in packaging("debian/afirewall.manpages"), "the manpage is not installed"


# TWO SUBJECTS, ONE DRILL, AND THAT IS NOT THE MASKING PATTERN. ch7-4 - that an upgrade cannot
# leave an old template beside a new base ruleset - is the CONSEQUENCE of ch7-2 rather than a
# separate check: if only afirewall.conf is a conffile there is no template for dpkg to keep. Two
# marks on one test means both move together, which is honest; two tests at one depth would let the
# passing one hide the failing one.
@pytest.mark.proves("ch7-2", depth="structural")
@pytest.mark.proves("ch7-4", depth="structural")
def test_only_what_the_admin_edits_is_a_conffile():
    """73 conffiles, measured on a host. A conffile is a promise that the admin's version wins,
    which is right for afirewall.conf — enabling a service IS the configuration — and wrong for a
    rules template, which the package revises as it learns things.

    Everything debhelper installs under /etc becomes a conffile, so this counts what the install
    file puts there rather than needing a host to ask.
    """
    install = packaging("debian/afirewall.install")
    under_etc = []
    for line in install.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("#!"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[-1].strip("/").startswith("etc/"):
            under_etc.append(parts[0])
    assert under_etc == ["afirewall.conf"], (
        f"these install under /etc and so become conffiles: {under_etc}. Only afirewall.conf is "
        "the admin's — a template kept at the admin's version across an upgrade puts an old "
        "template beside a new base.rules, which is the skew the package's own tests forbid.")


@pytest.mark.proves("ch7-3", depth="structural")
def test_the_package_ships_defaults_and_etc_overrides_them():
    """An override story rather than a prohibition. Somebody who needs a different ssh.rules still
    gets one; what they stop getting is their copy deciding what happens on every future upgrade."""
    install = packaging("debian/afirewall.install")
    for what in ("templates", "lists"):
        assert re.search(rf"^{what}\s+usr/share/afirewall\s*$", install, re.M), (
            f"{what} is not installed to /usr/share/afirewall, so there is no shipped copy for an "
            "/etc override to override, and the manpage's description of the layout stays fiction")
    source = (ROOT / "afirewall" / "afirewall.py").read_text()
    loader = re.search(r"FileSystemLoader\(\[(?P<paths>[^\]]*)\]", source)
    assert loader, "the template loader no longer takes a list of directories"
    paths = loader.group("paths")
    assert "usr/share/afirewall" in paths, (
        "the loader does not look in /usr/share/afirewall, so a host with no override finds no "
        f"templates at all. Searches: {paths.strip()}")
    assert paths.index("base_directory") < paths.index("usr/share/afirewall"), (
        "the shipped templates are searched before the base directory, so an /etc override would "
        "never win — which is the wrong way round")


@pytest.mark.proves("ch7-5", depth="structural")
def test_generated_rulesets_are_not_written_into_the_configuration():
    """ipv4.nft is derived from the config and rebuilt on every start. In /etc it is unowned by
    dpkg and churns under anything watching configuration; in a location that empties on boot it
    also cannot be loaded stale."""
    source = (ROOT / "afirewall" / "afirewall.py").read_text()
    written = re.search(r"output_name\s*=\s*(?P<expr>.+)", source)
    assert written, "cannot find where the generated ruleset is written"
    expr = written.group("expr")
    assert "base_directory" not in expr, (
        f"the generated ruleset is written into the base directory: {expr.strip()}. That puts "
        "machine-generated output in /etc, unowned by dpkg.")
    assert "/run/" in expr or "/var/lib/" in expr, (
        f"the generated ruleset goes somewhere that is neither /run nor /var/lib: {expr.strip()}")


@pytest.mark.proves("ch7-6", depth="structural")
def test_the_manual_describes_the_layout_that_exists():
    """The manpage already documents /usr/share/afirewall/templates and /usr/share/afirewall/lists.
    Documentation describing an intention is indistinguishable from documentation describing a
    fact, and a reader who follows it finds an empty directory."""
    manual = (ROOT / "doc" / "man" / "afirewall.8").read_text()
    install = packaging("debian/afirewall.install")
    claimed = sorted(set(re.findall(r"/usr/share/afirewall/[a-z]+", manual)))
    for path in claimed:
        leaf = path.rsplit("/", 1)[1]
        assert re.search(rf"^{leaf}\s+usr/share/afirewall\s*$", install, re.M), (
            f"the manual says {path} exists and nothing installs it. Either install it or stop "
            "describing it.")


@pytest.mark.proves("ch7-7", depth="integration")
def test_an_upgrade_asks_nothing_and_breaks_nothing():
    unwatched("ch7-7", "an old release installed, a template edited, an upgrade taken, and a look "
                       "at what survived — which is ch7-U2 and needs two releases and a disposable "
                       "host rather than a reading of the packaging")
