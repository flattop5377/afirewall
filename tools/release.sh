#!/bin/bash
# Cut a release. The sequence, in the repository rather than in somebody's head (ch5-1).
#
#   ./tools/release.sh 20260901.0.0            build only, publish nothing
#   ./tools/release.sh 20260901.0.0 --publish  and push it
#
# A packaging-only fix does NOT come through here: bump the Debian revision on debian/latest,
# `gbp buildpackage --git-tag`, and include the .deb. No new upstream version, no new tarball -
# pristine-tar regenerates the one that shipped. That is what ch5-5 is for.
set -euo pipefail

VERSION="${1:?usage: release.sh <upstream-version> [--publish]}"
PUBLISH="${2:-}"
REPO="$(git rev-parse --show-toplevel)"
DEBREPO="${DEBREPO:-$REPO/../debrepo}"
BUILD="$(mktemp -d)"
export DEBEMAIL="${DEBEMAIL:-Flattop5377@proton.me}"
export DEBFULLNAME="${DEBFULLNAME:-Flattop5377}"

say() { printf '\n== %s\n' "$*"; }

# COME BACK TO WHERE YOU STARTED. This walks the checkout through upstream/latest and debian/latest
# and used to leave it on the last one, which is a trap rather than an inconvenience: debian/latest
# carries master's files merged in, so work done there afterwards looks completely normal and is
# invisible until the next release merge either duplicates it or undoes it. It cost a commit
# immediately after the previous fix went in.
#
# ON A TRAP, so it holds when the script fails - which is exactly when somebody is most likely to be
# left somewhere they did not choose. AND ONLY IF THE TREE IS CLEAN: a run that stopped on a merge
# conflict should leave you standing in the conflict, not tidied away from it.
STARTED_ON="$(git -C "$REPO" rev-parse --abbrev-ref HEAD)"

finish() {
    code=$?
    now="$(git -C "$REPO" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "$STARTED_ON")"
    if [ "$now" != "$STARTED_ON" ]; then
        if [ -z "$(git -C "$REPO" status --porcelain)" ]; then
            git -C "$REPO" checkout -q "$STARTED_ON"
            echo "   (back on $STARTED_ON)"
        else
            echo
            echo "   LEFT ON $now WITH UNCOMMITTED WORK - that is where the failure is, so look"
            echo "   there rather than being moved away from it. When you are done:"
            echo "     git checkout $STARTED_ON"
        fi
    fi
    exit $code
}
trap finish EXIT

say "checking the tree is clean and the drills agree"
[ -z "$(git -C "$REPO" status --porcelain)" ] || { echo "working tree is dirty"; exit 1; }
git -C "$REPO" rev-parse --verify --quiet "refs/tags/upstream/latest/$VERSION" >/dev/null \
  && { echo "upstream/latest/$VERSION already exists"; exit 1; }
"$REPO/.venv/bin/python" -m pytest "$REPO/drills/test_ch5_release.py" -q

# THE MANPAGE'S VERSION STAMP, SET HERE BECAUSE IT IS THE ONLY MOMENT THAT KNOWS IT. Written by
# hand it is stale by definition: it names a release while sitting on the commit that precedes one,
# and on 2026-08-17 it was two releases behind and describing a subcommand that had changed. This
# is the version half of ch5-U5 - the options half, generating the page from get_parser(), is
# still open - and it is stamped on MASTER so the two layers do not disagree about a shared file,
# which the state drill would refuse.
say "stamping the manpage for $VERSION"
sed -i -E "s/^\.TH afirewall 8 \"[^\"]*\" \"[^\"]*\"/.TH afirewall 8 \"$(date +'%-d %b %Y')\" \"$VERSION\"/" \
    "$REPO/doc/man/afirewall.8"
if ! git -C "$REPO" diff --quiet -- doc/man/afirewall.8; then
    git -C "$REPO" commit -q -m "Stamp the manpage for $VERSION" -- doc/man/afirewall.8
fi

# THE SOURCE LAYER IS MERGED IN, NOT COPIED. master deletes nothing this layer owns, but a
# conflict here is a real question and the script stops rather than guessing: it means the two
# layers disagree about a file, and which side wins is not a decision a script should take.
say "merging master into upstream/latest"
git -C "$REPO" checkout -q upstream/latest
git -C "$REPO" merge --no-edit master
say "tagging upstream/latest/$VERSION"
git -C "$REPO" tag -a "upstream/latest/$VERSION" -m "Upstream $VERSION"

say "merging upstream/latest into debian/latest"
git -C "$REPO" checkout -q debian/latest
git -C "$REPO" merge --no-edit upstream/latest

say "changelog at $VERSION-1 — edit it to say what changed FOR SOMEBODY INSTALLING IT"
gbp dch --release --new-version="$VERSION-1" --distribution=unstable --force-distribution \
        --spawn-editor=never
# `eval`, BECAUSE $EDITOR IS A COMMAND LINE AND NOT A FILENAME. Quoted as one word this runs a
# program literally named `python3 /path/to/thing.py` and fails with "No such file or directory" -
# which is what happened on 20260817.0.0, after the merge and the tag, leaving the release
# half-made and the trap below to explain where. Anything a person sets EDITOR to may carry
# arguments, and `sensible-editor` still works unquoted.
eval "${EDITOR:-sensible-editor}" "\"$REPO/debian/changelog\""
git -C "$REPO" commit -q -am "Release $VERSION-1"

# --git-pristine-tar-commit is what makes this release rebuildable years later, and --git-tag is
# what records the packaging that shipped beside the source that shipped (ch5-4, ch5-7).
say "building"
gbp buildpackage -us -uc --git-export-dir="$BUILD" --git-pristine-tar-commit --git-tag
lintian -I "$BUILD/afirewall_${VERSION}-1_amd64.changes" || true

say "what the package actually contains"
dpkg-deb -c "$BUILD/afirewall_${VERSION}-1_all.deb" | awk '{print $6}' | grep -vE 'templates/|lists/'

if [ "$PUBLISH" != "--publish" ]; then
  say "built in $BUILD and published nothing. Re-run with --publish when it looks right."
  exit 0
fi

say "publishing to $DEBREPO"
reprepro -b "$DEBREPO" includedeb stable "$BUILD/afirewall_${VERSION}-1_all.deb"
git -C "$DEBREPO" add -A
git -C "$DEBREPO" commit -q -m "afirewall $VERSION-1"

# EXPLICIT REFSPECS, BECAUSE A BARE `git push` NEEDS UPSTREAM TRACKING AND FAILED WITHOUT IT.
# That is what went wrong on 20260816.2.0-1: debrepo's master had no tracking branch, the push
# errored, `set -e` ended the script there, and the afirewall push below never ran. Everything
# looked finished - archive updated, package built, both tags made - and nothing was public.
git -C "$DEBREPO" push origin HEAD:master

say "pushing branches and tags"
git -C "$REPO" push origin \
    refs/heads/master:refs/heads/master \
    refs/heads/upstream/latest:refs/heads/upstream/latest \
    refs/heads/debian/latest:refs/heads/debian/latest \
    refs/heads/pristine-tar:refs/heads/pristine-tar \
    "refs/tags/upstream/latest/$VERSION" \
    "refs/tags/debian/latest/$VERSION-1" 2>/dev/null \
  || git -C "$REPO" push origin master upstream/latest debian/latest pristine-tar --tags

# AND THEN CHECK, because an exit code is what the previous version trusted and it was not enough.
# A release that looks complete and is not is the failure this whole sequence exists to avoid, so
# the last thing it does is ask the remote what it has rather than assume the push said so.
say "verifying the remote has what was just built"
FAILED=0
for ref in master upstream/latest debian/latest pristine-tar; do
    local_sha="$(git -C "$REPO" rev-parse "$ref")"
    remote_sha="$(git -C "$REPO" ls-remote origin "refs/heads/$ref" | cut -f1)"
    if [ "$local_sha" != "$remote_sha" ]; then
        echo "   NOT PUSHED: $ref (local ${local_sha:0:8}, remote ${remote_sha:0:8})"
        FAILED=1
    fi
done
for tag in "upstream/latest/$VERSION" "debian/latest-$VERSION-1"; do
    if ! git -C "$REPO" ls-remote --tags origin | grep -q "refs/tags/$tag\$"; then
        echo "   NOT PUSHED: tag $tag"
        FAILED=1
    fi
done
debrepo_local="$(git -C "$DEBREPO" rev-parse HEAD)"
debrepo_remote="$(git -C "$DEBREPO" ls-remote origin HEAD | cut -f1)"
if [ "$debrepo_local" != "$debrepo_remote" ]; then
    echo "   NOT PUSHED: the archive"
    FAILED=1
fi
if [ "$FAILED" != "0" ]; then
    echo
    echo "THE RELEASE IS NOT PUBLISHED. Everything above succeeded locally; the push did not."
    exit 1
fi

say "published. Note that raw.githubusercontent caches for a few minutes, so an"
say "'apt update' straight after this can still serve the previous index. That is"
say "the CDN rather than the release - the verification above already asked the remote."
