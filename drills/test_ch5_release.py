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

#: THREE LAYERS, AND THIS IS THE SECOND ONE'S CONTENTS. master is the source. `upstream/latest`
#: adds what makes it deliverable as a Python project. `debian/latest` adds what makes it a Debian
#: package. Each layer is authored on - that is what a layer is for - and the rule is that it is
#: authored on for ITS OWN files and nothing else.
#:
#: The list is short on purpose. A file arriving here that nobody declared is how a `save` command
#: and a manpage came to be written on the packaging branch and never reached master.
#: EMPTY, AND THAT IS THE CLAIM RATHER THAN AN OVERSIGHT (2026-08-17). This held the files that
#: made afirewall deliverable as a Python project, and that deliverable was retired: nothing ever
#: built a wheel, `debian/rules` does not select pybuild, the built .deb has no dist-packages, and
#: almost everything this package IS - a conffile, a netfilter-persistent plugin, templates under
#: /usr/share, a manpage - lives where a wheel cannot put it.
#:
#: upstream/latest survives because gbp needs it: `debian/gbp.conf` names it as the upstream branch,
#: the orig tarball is built from it and pristine-tar regenerates that tarball byte-identically. So
#: the layer's job is to BE the source at a tag, and a layer that adds nothing is exactly what that
#: job wants. The set stays as the mechanism, at zero, so declaring something later is one edit
#: rather than a rewrite.
UPSTREAM_ONLY = set()


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


@pytest.mark.proves("ch5-1", depth="structural")
def test_the_release_sequence_is_in_the_repository():
    """A sequence somebody has to remember is a sequence somebody gets wrong at the version they
    most need to reproduce. This repository has already lost a manpage, a set of version bumps and
    a `save` command onto a branch nobody merges from, each of them a step somebody skipped.

    So the process is a file. What the drill holds is not that the file is good — it is that every
    step the chapter claims is actually in it, so the two cannot drift apart while both look
    maintained.
    """
    script = ROOT / "tools" / "release.sh"
    assert script.is_file(), (
        "there is no tools/release.sh, so the release sequence exists only in whatever the last "
        "person to cut one remembers")
    text = script.read_text()
    for phase, needle in (
            ("merge master into upstream/latest", "merge --no-edit master"),
            ("tag the upstream release (ch5-4)", "tag -a \"upstream/latest/"),
            ("merge upstream into the packaging layer", "merge --no-edit upstream/latest"),
            ("a Debian revision on the version (ch5-5)", "$VERSION-1"),
            ("commit the pristine-tar delta (ch5-7)", "--git-pristine-tar-commit"),
            ("tag the packaging that shipped (ch5-4)", "--git-tag"),
            ("publish to the archive", "includedeb"),
            ("push with an explicit refspec", "HEAD:master"),
            ("ask the remote what it actually has", "ls-remote"),
            ("put the checkout back where it started", "trap finish EXIT")):
        assert needle in text, f"tools/release.sh has no step that would {phase}"
    assert "--publish" in text, (
        "the script publishes unconditionally, so there is no way to look at what a release "
        "produced before it is public")

    # AND IT HAS TO CHECK ITS OWN PUSH. On 20260816.2.0-1 a bare `git push` in the archive needed
    # upstream tracking it did not have, the push errored, `set -e` ended the script there, and the
    # branch and tag push below it never ran. Archive updated, package built, both tags made, and
    # nothing public. An exit code was what that version trusted; asking the remote is what this
    # one does, and the drill pins it because the failure is invisible by construction.
    # COUNTED, NOT MERELY PRESENT. A first cut of this looked for one `ls-remote` and passed with
    # two of the three checks deleted, because the other two still matched — which is the same
    # too-loose-regex fault it was written to guard against. Three things get pushed and all three
    # have to be asked about: the branches, the tags, and the archive.
    asked = len(re.findall(r"ls-remote", text))
    assert asked >= 3, (
        f"the script asks the remote {asked} time(s). Three separate things are pushed - the "
        "branches, the release tags, and the archive - and each needs its own answer")
    assert re.search(r"NOT PUSHED", text) and re.search(r"^\s*exit 1", text, re.M), (
        "the script does not fail when the remote disagrees with what it just built. A release "
        "that looks complete and is not is the failure this whole sequence exists to avoid, and "
        "it has happened once already: a bare `git push` needed tracking it did not have, `set -e` "
        "ended the run, and everything after it silently did not happen")


@pytest.mark.proves("ch5-2", depth="structural")
def test_master_carries_the_software_and_upstream_carries_a_declared_few_more():
    """Both halves of the same claim, in ONE drill and at one depth.

    They were two, and ch5-2 read PROVEN off the half that held while the other was red — which is
    the masking this repository has now written down twice (afirewall ch1-6, ansible ch9-6) and
    walked into a third time. Two citations at the same depth reduce to one status and the passing
    one wins.
    """
    have("master")
    # Layer one holds the source and nothing about how anybody ships it.
    intruders = sorted(p for p in tree("master") if p.startswith("debian/"))
    assert not intruders, (
        f"master carries Debian packaging: {intruders}. It belongs on debian/latest, and master "
        "having it means every change to the software invites a decision about the package.")
    strays = sorted(tree("master") & UPSTREAM_ONLY)
    assert not strays, (
        f"master carries the deliverable layer's files: {strays}. They belong on upstream/latest — "
        "keeping them off master is what lets the source move without a packaging decision "
        "attached, and collapsing that boundary is how the licence file got two homes.")

    # Layer two adds NOTHING to layer one, which is what its job asks of it: gbp builds the orig
    # tarball from this branch, so anything here that master does not have ships in a tarball the
    # source cannot account for.
    have("upstream/latest")
    unexpected = sorted((tree("upstream/latest") - tree("master")) - UPSTREAM_ONLY)
    assert not unexpected, (
        f"upstream/latest holds files master does not: {unexpected}. That branch is the source at "
        "a tag - gbp builds the orig tarball from it - so a file here and not on master ships in a "
        "tarball the source cannot account for. Put it on master, or declare it in UPSTREAM_ONLY "
        "deliberately.")


@pytest.mark.proves("ch5-3", depth="structural")
def test_the_deliverable_layer_is_only_ever_authored_for_its_own_files():
    """A layer is a branch you DO commit to — that is what makes it a layer rather than a
    destination. The rule is not that upstream/latest holds no commits of its own; it is that every
    one of them touches only the files that layer owns.

    SCOPED TO SINCE THE LAST RELEASE, deliberately. Before that boundary the rule was broken —
    `Added save command`, `Adding man page for afirewall`, `Update project, and website` were all
    authored here and the source never got them, which is how master and upstream came to disagree
    about three files. That is history and a permanently red drill teaches nobody anything. What
    this holds is that it has not happened SINCE, which is the part anybody can still act on.
    """
    have("master"); have("upstream/latest")
    tags, _ = git("tag", "--list", "upstream/latest/*")
    releases = sorted(tags.splitlines())
    if not releases:
        pytest.skip("no release tag to measure from")
    since = releases[-1]
    out, _ = git("log", "--format=%h %s", "--no-merges", "upstream/latest", f"^{since}", "^master")
    strayed = []
    for line in [ln for ln in out.splitlines() if ln]:
        sha = line.split()[0]
        touched, _ = git("show", "--name-only", "--format=", sha)
        # RETIRING A FILE THAT ONLY EVER LIVED HERE IS NOT AUTHORING ONE. A file this layer owned
        # can only be deleted on this layer, so the commit that removes it must be made here — and
        # it leaves nothing for master to be missing, which is the harm this rule exists to
        # prevent. Paths gone from BOTH branches are dropped for that reason; anything still
        # present is judged as before. Found when the Python deliverable was retired and the only
        # possible commit doing it read as a violation.
        present = tree("master") | tree("upstream/latest")
        outside = sorted(set(f for f in touched.splitlines() if f) & present - UPSTREAM_ONLY)
        if outside:
            strayed.append(f"{line}\n      touches {outside}")
    assert not strayed, (
        f"since {since}, commit(s) on upstream/latest have changed files that layer does not "
        f"own:\n  " + "\n  ".join(strayed[:6])
        + f"\n\nupstream/latest adds {sorted(UPSTREAM_ONLY)} to the source and nothing else. "
          "Anything else changed here does not reach master, and the next release has to reconcile "
          "the two rather than merge them.")


@pytest.mark.proves("ch5-3", depth="structural")
def test_no_shared_file_differs_between_the_layers():
    """The state the drill above cannot see, and the reason it is a SECOND test rather than a
    stricter first one.

    `test_the_deliverable_layer_is_only_ever_authored_for_its_own_files` asks whether anybody has
    strayed SINCE the last release, which is right for commits and blind to what straying already
    left behind — and every release resets that boundary, so a violation that survives one cut
    becomes permanently invisible. `requirements.txt` was authored on upstream/latest in April 2025,
    fell behind the boundary, and sat diverged for sixteen months until both layers moved in the
    same release and it conflicted.

    THIS ASKS ABOUT NOW INSTEAD OF ABOUT HISTORY. A file the layers disagree about is a merge
    conflict waiting for the next release, whenever it was created and whoever created it, and a
    question about the present cannot be aged out.

    It is not the same claim as the one above wearing a different scope: that one is about
    discipline and this one is about state, and a repository can pass either while failing the
    other. Both cite ch5-3 because a layer that only authors its own files and a layer whose shared
    files match are the two halves of one boundary being real.
    """
    have("master"); have("upstream/latest")
    out, _ = git("diff", "--name-only", "master", "upstream/latest")
    diverged = sorted(f for f in out.splitlines() if f and f not in UPSTREAM_ONLY)
    assert not diverged, (
        f"master and upstream/latest disagree about {len(diverged)} file(s) that neither layer "
        f"owns exclusively:\n  " + "\n  ".join(diverged)
        + f"\n\nOnly {sorted(UPSTREAM_ONLY)} may differ. Anything else here will conflict at the "
          "next release that touches it — decide which layer owns it and make the other match, or "
          "declare it above if it genuinely belongs to the deliverable layer alone.")


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


@pytest.mark.proves("ch5-8", depth="structural")
def test_the_newest_release_left_a_complete_set_of_artifacts():
    """What a release that ran cleanly leaves behind: a version, tagged in both places, with a
    tarball anybody can regenerate. A missing one is a step that did not happen, and the step that
    does not happen is always the one nobody notices until they need it.

    This reads the repository rather than the archive on purpose. Whether a package is fetchable
    depends on a CDN and a network, and a drill that goes red because raw.githubusercontent is
    still serving a cached index has taught nobody anything about the release.
    """
    have("debian/latest")
    version, _ = git("show", "debian/latest:debian/changelog")
    top = version.splitlines()[0]
    full = top.split("(")[1].split(")")[0]
    upstream = full.rsplit("-", 1)[0]

    tags, _ = git("tag")
    tags = set(tags.splitlines())
    assert f"upstream/latest/{upstream}" in tags, (
        f"debian/changelog is at {full} and there is no upstream/latest/{upstream} tag, so the "
        "source that shipped is not recorded")
    assert f"debian/latest-{full}" in tags, (
        f"debian/changelog is at {full} and there is no debian/latest-{full} tag, so the packaging "
        "that shipped is not recorded")

    have("pristine-tar")
    deltas, _ = git("ls-tree", "--name-only", "pristine-tar")
    assert any(upstream in d and d.endswith(".delta") for d in deltas.splitlines()), (
        f"no pristine-tar delta for {upstream}, so the tarball that shipped cannot be regenerated "
        "and a bug reported against this version gets guessed at rather than built")
