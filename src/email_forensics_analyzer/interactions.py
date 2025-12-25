from collections import defaultdict
from datetime import datetime

def build_interactions(core_rows):
    """
    core_rows: list of dicts from parser.extract_core_fields
    Returns edge dict keyed by (sender, recipient).
    """
    edges = {}
    for r in core_rows:
        sender = (r.get("sender_email") or "").lower()
        if not sender:
            continue
        dt = None
        if r.get("date_iso"):
            try:
                dt = datetime.fromisoformat(r["date_iso"])
            except Exception:
                dt = None
        for rcpt in r.get("recipients", []) or []:
            rcpt = (rcpt or "").lower()
            if not rcpt:
                continue
            key = (sender, rcpt)
            if key not in edges:
                edges[key] = {"count": 0, "first_seen": None, "last_seen": None}
            edges[key]["count"] += 1
            if dt:
                if edges[key]["first_seen"] is None or dt < edges[key]["first_seen"]:
                    edges[key]["first_seen"] = dt
                if edges[key]["last_seen"] is None or dt > edges[key]["last_seen"]:
                    edges[key]["last_seen"] = dt
    return edges

def edges_to_rows(edges):
    out = []
    for (s, r), v in edges.items():
        out.append({
            "sender": s,
            "recipient": r,
            "count": v["count"],
            "first_seen": v["first_seen"].isoformat() if v["first_seen"] else "",
            "last_seen": v["last_seen"].isoformat() if v["last_seen"] else "",
        })
    out.sort(key=lambda x: (-x["count"], x["sender"], x["recipient"]))
    return out
