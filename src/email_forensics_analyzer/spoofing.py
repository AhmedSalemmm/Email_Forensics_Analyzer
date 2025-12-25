import re
from .utils import decode_mime_header, domain_of

_AUTH_RES_PAT = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)", re.I)

def parse_authentication_results(msg):
    """
    Parse Authentication-Results-ish headers.
    Returns dict like {"spf":"pass","dkim":"fail","dmarc":"pass"} when found.
    """
    results = {}
    for hdr in ["Authentication-Results", "ARC-Authentication-Results"]:
        vals = msg.get_all(hdr, failobj=[])
        for v in vals:
            s = decode_mime_header(v)
            for m in _AUTH_RES_PAT.finditer(s):
                results[m.group(1).lower()] = m.group(2).lower()
    # fallback: Received-SPF sometimes exists
    if "spf" not in results:
        vals = msg.get_all("Received-SPF", failobj=[])
        for v in vals:
            s = decode_mime_header(v)
            # common format: "pass (...)" or "fail (...)"
            m = re.search(r"^\s*([a-zA-Z]+)\b", s)
            if m:
                results["spf"] = m.group(1).lower()
    return results

def extract_received_hops(msg):
    rec = msg.get_all("Received", failobj=[])
    return [decode_mime_header(x) for x in rec]

def indicator_rules(core, msg):
    """
    Returns:
      indicators: dict[str,bool]
      details: dict[str,str] small text explanation
      score: int (higher = more suspicious)
    """
    indicators = {}
    details = {}
    score = 0

    from_domain = core.get("sender_domain", "")
    return_path = core.get("return_path", "")
    reply_to = core.get("reply_to", "")

    return_path_domain = domain_of(return_path.strip("<> ")) if return_path else ""
    reply_to_domain = domain_of(reply_to) if reply_to else ""

    # 1) Auth results
    auth = parse_authentication_results(msg)
    spf = auth.get("spf", "")
    dkim = auth.get("dkim", "")
    dmarc = auth.get("dmarc", "")

    if spf in {"fail","softfail","neutral","none","permerror","temperror"}:
        indicators["spf_suspicious"] = True
        details["spf_suspicious"] = f"SPF={spf}"
        score += 3
    else:
        indicators["spf_suspicious"] = False

    if dkim in {"fail","none","permerror","temperror"}:
        indicators["dkim_suspicious"] = True
        details["dkim_suspicious"] = f"DKIM={dkim}"
        score += 3
    else:
        indicators["dkim_suspicious"] = False

    if dmarc in {"fail","none","permerror","temperror"}:
        indicators["dmarc_suspicious"] = True
        details["dmarc_suspicious"] = f"DMARC={dmarc}"
        score += 3
    else:
        indicators["dmarc_suspicious"] = False

    # 2) Domain mismatch checks
    if from_domain and return_path_domain and from_domain != return_path_domain:
        indicators["from_returnpath_mismatch"] = True
        details["from_returnpath_mismatch"] = f"From={from_domain} Return-Path={return_path_domain}"
        score += 2
    else:
        indicators["from_returnpath_mismatch"] = False

    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        indicators["replyto_domain_mismatch"] = True
        details["replyto_domain_mismatch"] = f"From={from_domain} Reply-To={reply_to_domain}"
        score += 2
    else:
        indicators["replyto_domain_mismatch"] = False

    # 3) Message-ID domain mismatch
    msgid = (core.get("message_id","") or "").strip()
    mid_dom = ""
    if "@" in msgid:
        mid_dom = msgid.split("@", 1)[1].strip(">").strip().lower()
    if from_domain and mid_dom and from_domain not in mid_dom and mid_dom not in from_domain:
        indicators["messageid_domain_mismatch"] = True
        details["messageid_domain_mismatch"] = f"From={from_domain} Message-ID domain={mid_dom}"
        score += 1
    else:
        indicators["messageid_domain_mismatch"] = False

    # 4) Routing heuristics
    received = extract_received_hops(msg)
    if len(received) <= 1:
        indicators["few_received_hops"] = True
        details["few_received_hops"] = f"Received hop count={len(received)}"
        score += 1
    else:
        indicators["few_received_hops"] = False

    # 5) Display-name vs address heuristic (very light)
    sender_name = (core.get("sender_name","") or "").lower()
    sender_email = (core.get("sender_email","") or "").lower()
    if sender_name and sender_email and ("@" in sender_email):
        local = sender_email.split("@",1)[0]
        if len(sender_name) > 3 and local not in sender_name and from_domain and from_domain.split(".")[0] in sender_name:
            # e.g., name says "paypal" but email is random@otherdomain
            if from_domain and from_domain not in sender_email:
                indicators["name_impersonation_hint"] = True
                details["name_impersonation_hint"] = f"Display name contains brand-like token; email={sender_email}"
                score += 1
            else:
                indicators["name_impersonation_hint"] = False
        else:
            indicators["name_impersonation_hint"] = False
    else:
        indicators["name_impersonation_hint"] = False

    # Final label
    if score >= 7:
        risk = "high"
    elif score >= 4:
        risk = "medium"
    elif score >= 1:
        risk = "low"
    else:
        risk = "none"

    return indicators, details, score, risk
