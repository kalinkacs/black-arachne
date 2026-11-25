"""Parallel, evidence-scoped defensive checks for one SSH investigation."""

from concurrent.futures import ThreadPoolExecutor

from .role_runtime import RoleFailure


SPECIALTIES = {
    "change_record": ("Athos", {"deployment", "change_verified", "change_disputed"}),
    "identity_record": ("Porthos", {"identity_verified", "identity_disputed"}),
    "activity_record": ("Aramis", {"ssh_failure", "privileged_activity", "privilege_denied"}),
}


def review(anchor, observations, profile, inspect):
    def specialist(key):
        name, kinds = SPECIALTIES[key]
        evidence = tuple(event for event in observations if event.kind in kinds)
        try:
            result = inspect(key, anchor, evidence, dict(profile))
        except RoleFailure:
            return {"check": key, "specialist": name, "state": "unknown", "evidence_ids": [], "available": False}
        return {**result, "specialist": name, "available": True}

    with ThreadPoolExecutor(max_workers=len(SPECIALTIES)) as workers:
        return dict(zip(SPECIALTIES, workers.map(specialist, SPECIALTIES)))
