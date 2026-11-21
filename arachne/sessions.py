"""Keep adjacent events from being mistaken for events of the current SSH session."""

from .events import ANCHOR_KINDS, episode_window
from .provenance import VERIFICATION_KINDS


def attribution(anchor, events, verified):
    lower, upper = episode_window(anchor)
    linked, context, excluded = [], [], []
    for event in events:
        if event.id == anchor.id or (event.host, event.actor) != (anchor.host, anchor.actor):
            continue
        if not lower <= event.timestamp <= upper:
            continue
        if event.machine_id is not None and anchor.machine_id is not None and event.machine_id != anchor.machine_id:
            excluded.append(event.id)
        elif event.kind in VERIFICATION_KINDS:
            if event.id in verified:
                context.append(event.id)
        elif event.kind in ANCHOR_KINDS:
            continue
        elif event.kind == "deployment" and not event.session_key:
            # A declaration offers a candidate explanation. Authorization
            # requires a separately confirmed record for this anchor.
            context.append(event.id)
        elif anchor.session_key and (event.machine_id, event.session_key) == (anchor.machine_id, anchor.session_key):
            linked.append(event.id)
        else:
            excluded.append(event.id)
    return {"status": "bound" if anchor.session_key else "unbound", "linked": linked,
            "context": context, "excluded": excluded}


def attributed_events(anchor, events, scope):
    allowed = {anchor.id, *scope["linked"], *scope["context"]}
    return [event for event in events if event.id in allowed]
