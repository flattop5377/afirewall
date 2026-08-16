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

say "checking the tree is clean and the drills agree"
[ -z "$(git -C "$REPO" status --porcelain)" ] || { echo "working tree is dirty"; exit 1; }
git -C "$REPO" rev-parse --verify --quiet "refs/tags/upstream/latest/$VERSION" >/dev/null \
  && { echo "upstream/latest/$VERSION already exists"; exit 1; }
"$REPO/.venv/bin/python" -m pytest "$REPO/drills/test_ch5_release.py" -q

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
"${EDITOR:-sensible-editor}" "$REPO/debian/changelog"
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
git -C "$DEBREPO" push

say "pushing branches and tags"
git -C "$REPO" push origin master upstream/latest debian/latest pristine-tar --tags

# raw.githubusercontent caches for a few minutes, so an install straight after a push still sees
# the previous index. That is the CDN and not the release; wait it out before believing a failure.
say "done. `apt update` may serve the previous index for a few minutes."
