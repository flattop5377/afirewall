"""The other half of the vocabulary: how a drill says it cannot run yet.

A claim nothing cites is **absent** from the board. A claim cited by a skipping drill is
**unwatched** — the observation is named, and nobody has taken it. Those are different facts about
a project and the board is right to spell them differently.

Most drills here skip, and that is not a defect being tolerated. This fleet was built before it was
specified, so the honest position is a written claim and a named observation that has not been made
— not an assertion dressed as a test.
"""

import pytest


def unwatched(subject: str, what_would_run: str) -> None:
    """Name the observation this claim waits on, and skip until somebody can take it."""
    pytest.skip(f"UNWATCHED[{subject}] — needs: {what_would_run}")
