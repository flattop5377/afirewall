"""Chapter 5 drills — whether a release is a linear pass or a reconciliation.

The argument is in ``spec/diagrams/chapter-05-release.md`` and is not repeated here.

**THESE READ THE BRANCHES, NOT A DOCUMENT.** A written release process is a description somebody
has to remember; these are the same claims asked of git, so a branch that drifts is a red drill
rather than a surprise at the worst moment. They skip rather than fail where a branch is absent,
because a shallow or partial checkout is not evidence of drift.
"""

import pathlib
import re
import shutil
import subprocess

import pytest

from undrilled import unwatched

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: What `upstream/latest` may hold that `master` does not. THE LIST IS THE POINT: master carries the
#: software and what describes it, the packaging-adjacent files sit one branch further out, and the
#: difference is a decision rather than a residue. Anything else appearing here is drift.
UPSTREAM_ONLY = {"DESCRIPTION.txt", "pyproject.toml"}


def git(*args):
    done = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, encoding="UTF-8")
    return done.stdout.strip(), done.returncode


def have(ref):
    _, code = git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    if code != 0:
        pytest.skip(f"{ref} is not in this checkout, which is not evidence about it")


def tree(ref):
    out, _ = git("ls-tree", "-r", "--name-only", ref)
    return set(out.splitlines())


@pytest.mark.proves("ch5-1", depth="unit")
def test_a_release_can_be_cut_by_somebody_who_has_not_done_it_before():
    unwatched("ch5-1", "somebody following the chapter and reaching a published package without "
                       "asking a question — the measure is a person's experience of the process "
                       "and cannot be taken from inside the repository")


@pytest.mark.proves("ch5-2", depth="structural")
def test_master_carries_the_software_and_upstream_carries_a_declared_few_more():
    """Both halves of the same claim, in ONE drill and at one depth.

    They were two, and ch5-2 read PROVEN off the half that held while the other was red — which is
    the masking this repository has now written down twice (afirewall ch1-6, ansible ch9-6) and
    walked into a third time. Two citations at the same depth reduce to one status and the passing
    one wins.
    """
    have("master")
    # `debian/` is Debian's opinion of the software rather than the software, and keeping it off
    # master is what lets master move without a packaging decision attached.
    intruders = sorted(p for p in tree("master") if p.startswith("debian/"))
    assert not intruders, (
        f"master carries packaging: {intruders}. It belongs on debian/latest, and master having it "
        "means every change to the software invites a decision about the package.")

    # And the difference the other way has to be a decision rather than a residue. A short declared
    # list is a choice somebody made; an undeclared one is how the licence file ended up with two
    # homes and five renames.
    have("upstream/latest")
    unexpected = sorted((tree("upstream/latest") - tree("master")) - UPSTREAM_ONLY)
    assert not unexpected, (
        f"upstream/latest holds files master does not and that nobody declared: {unexpected}. "
        f"The declared list is {sorted(UPSTREAM_ONLY)} — either add to it deliberately, or the "
        "file belongs on master.")


@pytest.mark.proves("ch5-3", depth="structural")
def test_nothing_is_authored_on_a_destination_branch():
    """The rule the whole chapter rests on, and the one currently broken.

    upstream/latest exists to receive master. Commits that appear there and nowhere else are work
    that has to find its way home, and this repository has 26 of them — a manpage, version bumps, a
    website change. That single fact explains the licence confusion, the pyproject.toml that could
    not be edited without breaking dpkg-source, and the conflicts a release hits today.
    """
    have("master"); have("upstream/latest")
    out, _ = git("log", "--oneline", "--no-merges", "upstream/latest", "^master")
    orphans = [ln for ln in out.splitlines() if ln]
    assert not orphans, (
        f"{len(orphans)} commit(s) exist on upstream/latest and nowhere else:\n  "
        + "\n  ".join(orphans[:10])
        + ("\n  ..." if len(orphans) > 10 else "")
        + "\nupstream/latest is a destination. Work authored there does not reach master, and a "
          "release then has to reconcile the two rather than merge them.")


@pytest.mark.proves("ch5-4", depth="structural")
def test_every_release_is_recorded_by_a_pair_of_tags():
    """A tag says what shipped and offers nowhere to put something new. A branch does the opposite,
    and all three release branches this repository made had to be merged home."""
    have("master")
    out, _ = git("tag")
    tags = set(out.splitlines())
    upstream = {t.rsplit("/", 1)[1] for t in tags if t.startswith("upstream/latest/")}
    assert upstream, "no upstream release tags at all, so nothing records what was ever shipped"
    for version in sorted(upstream):
        assert any(t.startswith(f"debian/latest-{version}") for t in tags), (
            f"upstream/latest/{version} has no debian/latest-{version} beside it, so the source "
            "that shipped is recorded and the packaging that shipped with it is not")


@pytest.mark.proves("ch5-5", depth="structural")
def test_the_format_allows_a_packaging_only_release():
    """A wrong dependency or a bad .install line should cost a Debian revision, not a fake upstream
    version. `3.0 (native)` has no revision, which is why every packaging fix used to force one."""
    have("debian/latest")
    fmt, _ = git("show", "debian/latest:debian/source/format")
    assert "native" not in fmt, (
        f"the source format is {fmt.strip()!r}, which has no Debian revision — so a packaging-only "
        "fix cannot be released without inventing an upstream version that changed nothing")


@pytest.mark.proves("ch5-6", depth="structural")
def test_the_nft_the_templates_need_is_declared():
    """The generated ruleset is the artifact and it has to parse on the target's nftables, so nft's
    VERSION is a dependency of the output. A host with an older one installs cleanly and then fails
    at `afirewall start`, with no firewall — the worst moment to find out."""
    have("debian/latest")
    control, _ = git("show", "debian/latest:debian/control")
    depends = re.search(r"^Depends:(?P<d>.*(?:\n[ \t].*)*)", control, re.M)
    assert depends, "debian/control declares no Depends at all"
    line = depends.group("d")
    assert re.search(r"nftables\s*\(\s*>=", line), (
        "Depends names nftables with no version. The templates already use `typeof` in set "
        "definitions, `ct count`, dynamic sets and `meta skuid`, none of which have always "
        f"existed. Declared: {line.strip()!r}")


#: Where an nft of a given version can be obtained. THIS IS A LOOKUP AND NOT A SOURCE OF TRUTH:
#: `debian/control` decides the floor, and this only says where to find that nft. A floor set to a
#: version absent from here makes the drill skip and say so, which is honest - it is better than
#: silently testing a version nobody declared.
NFT_IMAGES = {
    "0.9.3": "ubuntu:20.04",
    "0.9.8": "debian:bullseye",
    "1.0.2": "ubuntu:22.04",
    "1.0.6": "debian:bookworm",
    "1.1.3": "debian:trixie",
}


def declared_floor():
    """The version `debian/control` says is required, which is the only authority on it."""
    have("debian/latest")
    control, _ = git("show", "debian/latest:debian/control")
    found = re.search(r"nftables\s*\(\s*>=\s*([0-9][0-9.]*)\s*\)", control)
    assert found, "debian/control declares no nftables floor, which is the other half of ch5-6"
    return found.group(1)


def floor_image(version):
    """A cached image with that nft installed, built once and reused.

    Built rather than pulled-and-apt-installed every run, because a drill that takes a minute is a
    drill somebody starts skipping.
    """
    base = NFT_IMAGES.get(version)
    if base is None:
        pytest.skip(f"no image known to carry nft {version} — add one to NFT_IMAGES, or this "
                    f"cannot check the floor debian/control declares")
    tag = f"afirewall-nft-floor:{version}"
    exists = subprocess.run(["docker", "image", "inspect", tag],
                            capture_output=True).returncode == 0
    if not exists:
        build = subprocess.run(
            ["docker", "build", "-q", "-t", tag, "-"],
            input=f"FROM {base}\nRUN apt-get -qq update && "
                  f"DEBIAN_FRONTEND=noninteractive apt-get -qq install -y nftables\n",
            capture_output=True, encoding="UTF-8", timeout=600)
        if build.returncode != 0:
            pytest.skip(f"cannot build an nft {version} image: {build.stderr.strip()[:200]}")
    return tag


@pytest.mark.proves("ch5-6", depth="integration")
def test_the_ruleset_parses_on_the_nft_the_package_demands(tmp_path):
    """THE MEASUREMENT, KEPT RATHER THAN RECORDED. ch5-U1 was settled once by hand and that made
    `debian/control` right on one afternoon. Every template added since - by `afirewall
    add-service`, or by whatever the namespace work needs - can raise the floor without anything
    noticing: the templates render, this machine's nft accepts them, and the constraint goes on
    claiming a version nobody has retested.

    So the floor is re-measured rather than remembered. A red here is not an error to explain away;
    it is the question `ch5-6` exists to ask, and it has exactly two honest answers - change the
    template, or raise the floor in debian/control.

    The reading that produced the current number is worth keeping in view: 0.9.3 and 0.9.8 fail,
    1.0.2 and later parse, and the construct that draws the line is `tcp flags urg / urg,ack`
    rather than any of `typeof`, `ct count`, dynamic sets or `meta skuid`, all of which parse on
    0.9.3. Nothing about which feature matters was guessable from reading the templates.
    """
    if not shutil.which("docker"):
        pytest.skip("docker is not available, so no other nft can be reached from here")
    version = declared_floor()
    image = floor_image(version)

    import sys
    sys.path.insert(0, str(ROOT / "test"))
    from test_afirewall import render_everything
    for family in ("ipv4", "ipv6"):
        (tmp_path / f"{family}.nft").write_text(render_everything(family))
    (tmp_path).chmod(0o755)

    complaints = []
    for family in ("ipv4", "ipv6"):
        done = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{tmp_path}:/r:ro", image,
             "nft", "-c", "-f", f"/r/{family}.nft"],
            capture_output=True, encoding="UTF-8", timeout=300)
        # `User does not exist` is the CONTAINER lacking a service account, not a version problem -
        # a real host has disable_services_missing_their_users() remove those before generation.
        # Filtering it out is why this asserts on syntax rather than on a clean exit.
        for line in done.stderr.splitlines():
            if "Error:" in line and "User does not exist" not in line:
                complaints.append(f"{family}: {line.strip()}")

    assert not complaints, (
        f"the generated ruleset does not parse on nft {version}, which is what "
        f"`Depends: nftables (>= {version})` promises a host it will work on:\n  "
        + "\n  ".join(complaints[:6])
        + f"\n\nTwo answers and no third: change the template so it parses on {version}, or raise "
          "the floor in debian/control to the oldest version that does. Raising it drops support "
          "for hosts that were working; changing the template keeps them.")


@pytest.mark.proves("ch5-7", depth="structural")
def test_what_shipped_can_be_rebuilt():
    """A release nobody can reproduce is a release you cannot debug: a bug report against an old
    version gets guessed at rather than built and stepped through."""
    have("pristine-tar")
    out, _ = git("ls-tree", "--name-only", "pristine-tar")
    deltas = [f for f in out.splitlines() if f.endswith(".delta")]
    assert deltas, ("the pristine-tar branch carries no deltas, so no released tarball can be "
                    "regenerated from this repository")
    out, _ = git("tag")
    newest = sorted(t.rsplit("/", 1)[1] for t in out.splitlines()
                    if t.startswith("upstream/latest/"))[-1]
    assert any(newest in d for d in deltas), (
        f"the newest release {newest} has no pristine-tar delta, so the one version most likely to "
        f"be reported against cannot be rebuilt. Deltas present: {deltas}")


@pytest.mark.proves("ch5-8", depth="integration")
def test_a_release_needs_no_decisions():
    unwatched("ch5-8", "a release cut end to end with no conflict and no question — which cannot "
                       "be observed until ch5-U2 is resolved, because a trial merge of master into "
                       "upstream/latest stops on three files today")
