"""The typed, read-only evidence vocabulary used in the signal laboratory."""

from dataclasses import dataclass


ASSURANCES = ("identity", "change", "privilege")
PROFILE_FIELDS = {"declared_change", "prior_failures", "privileged_activity", "repeated_privilege_denials"}


@dataclass(frozen=True)
class Measurement:
    identifier: str
    requirement: str


MEASUREMENTS = {
    ("identity",): Measurement("identity_session", "Independent identity assertion bound to this SSH session."),
    ("change",): Measurement("change_session", "Independent change approval whose scope includes this SSH session."),
    ("privilege",): Measurement("privilege_operation", "Independent privilege authorization for this operation."),
    ("change", "identity"): Measurement("identity_change_session",
        "Independent assertion binding the approved change and authenticated operator to the same SSH session."),
    ("identity", "privilege"): Measurement("identity_privilege_operation",
        "Independent assertion binding the authenticated operator to the privilege authorization for this operation."),
    ("change", "privilege"): Measurement("change_privilege_operation",
        "Independent assertion that this privileged operation was within the scope of the approved change."),
}


def checked_focus(value, *, first=False, adopted=None):
    if not isinstance(value, dict) or set(value) != {"primary", "secondary"}:
        raise ValueError("Invalid evidence proposal")
    primary, secondary = value["primary"], value["secondary"]
    if primary not in ASSURANCES or (secondary is not None and secondary not in ASSURANCES) or primary == secondary:
        raise ValueError("Unsupported assurances in evidence proposal")
    if (first and secondary is not None) or (adopted is not None and primary != adopted):
        raise ValueError("Evidence proposal did not preserve its assigned perspective")
    return value


def measurement(focus):
    return MEASUREMENTS[tuple(sorted(item for item in focus.values() if item is not None))]


def local_focus(profile, perspective, *, own=None, peer=None):
    if perspective == "legitimate":
        priority = "change" if profile["declared_change"] else "identity"
    else:
        priority = "identity"
        if profile["repeated_privilege_denials"]:
            priority = "privilege"
        elif profile["declared_change"] and not (profile["prior_failures"] or profile["privileged_activity"]):
            priority = "change"
    if own is None:
        return {"primary": priority, "secondary": None}
    if peer is not None:
        # Keep the borrowed premise while looking for what it leaves open.
        qualification = own
        if own == peer == "identity" and perspective == "security" and profile["privileged_activity"]:
            qualification = "privilege"
        return {"primary": peer, "secondary": qualification if qualification != peer else None}
    # The single-agent control gets a second turn with the same vocabulary.
    # It can also ask for a combined assurance using observable context.
    secondary = None
    if profile["declared_change"] and profile["prior_failures"]:
        secondary = "identity"
    elif profile["repeated_privilege_denials"]:
        secondary = "privilege"
    return {"primary": own, "secondary": secondary if secondary != own else None}
