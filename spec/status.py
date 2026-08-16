"""The claim vocabulary — deliberately minimal, and borrowed from sibling `holdfast`.

A chapter authors nothing but the existence of its claims. **Status is derived, never written.**
For this repository the derivation is fleet-shaped: a claim reads as proven only when something
that ran cited it and passed. Until then it reads UNPROVEN, which is the correct state for a spec
describing hosts that were configured by hand before anybody wrote the claim down.

There is intentionally no ``done()``. That would be authored status, and an authored status is a
note that agrees with itself.
"""


def story(id: str) -> None:
    """Declare a claim node. Its status is derived from a citing drill, never stated here."""
