import mailbox
import hashlib
from email import policy
from email.parser import BytesParser

from .utils import decode_mime_header, addr_list, parse_email_date, domain_of, normalize_subject


def iter_mbox_messages(mbox_path: str):
    """Yield email.message.EmailMessage objects from an mbox file."""
    mbox = mailbox.mbox(mbox_path, factory=None, create=False)
    for key in mbox.iterkeys():
        msg = mbox.get_message(key)
        raw = msg.as_bytes()
        eml = BytesParser(policy=policy.default).parsebytes(raw)
        yield eml


def message_fingerprint(msg) -> str:
    """Stable-ish identifier for evidence folder naming."""
    mid = decode_mime_header(msg.get("Message-ID", "")) or ""
    if mid:
        return hashlib.sha1(mid.encode("utf-8", errors="ignore")).hexdigest()[:16]
    basis = (
        decode_mime_header(msg.get("From", ""))
        + "|"
        + decode_mime_header(msg.get("To", ""))
        + "|"
        + decode_mime_header(msg.get("Date", ""))
        + "|"
        + decode_mime_header(msg.get("Subject", ""))
    )
    return hashlib.sha1(basis.encode("utf-8", errors="ignore")).hexdigest()[:16]


def extract_core_fields(msg):
    from_raw = decode_mime_header(msg.get("From", ""))
    to_raw = decode_mime_header(msg.get("To", ""))
    cc_raw = decode_mime_header(msg.get("Cc", ""))
    bcc_raw = decode_mime_header(msg.get("Bcc", ""))
    subject_raw = decode_mime_header(msg.get("Subject", ""))
    date_raw = decode_mime_header(msg.get("Date", ""))
    msgid = decode_mime_header(msg.get("Message-ID", ""))
    return_path = decode_mime_header(msg.get("Return-Path", ""))
    reply_to = decode_mime_header(msg.get("Reply-To", ""))

    from_addrs = addr_list(from_raw)
    to_addrs = addr_list(to_raw)
    cc_addrs = addr_list(cc_raw)
    bcc_addrs = addr_list(bcc_raw)

    sender_email = from_addrs[0][1] if from_addrs else ""
    sender_name = from_addrs[0][0] if from_addrs else ""

    dt = parse_email_date(date_raw)
    dt_iso = dt.isoformat() if dt else ""

    recipients = [a for _, a in (to_addrs + cc_addrs + bcc_addrs)]
    recipients = list(dict.fromkeys([r.lower() for r in recipients if r]))  # unique

    return {
        "from_raw": from_raw,
        "to_raw": to_raw,
        "cc_raw": cc_raw,
        "bcc_raw": bcc_raw,
        "subject": subject_raw,
        "subject_norm": normalize_subject(subject_raw),
        "date_raw": date_raw,
        "date_iso": dt_iso,
        "message_id": msgid,
        "return_path": return_path,
        "reply_to": reply_to,
        "sender_email": sender_email,
        "sender_name": sender_name,
        "sender_domain": domain_of(sender_email),
        "recipients": recipients,
        "to": [a for _, a in to_addrs],
        "cc": [a for _, a in cc_addrs],
        "bcc": [a for _, a in bcc_addrs],
    }


def extract_headers_structured(msg):
    """Extract a forensics-relevant header subset + all Received lines."""
    hdrs = {}
    keys = [
        "From",
        "To",
        "Cc",
        "Bcc",
        "Subject",
        "Date",
        "Message-ID",
        "Return-Path",
        "Reply-To",
        "Received",
        "Received-SPF",
        "Authentication-Results",
        "DKIM-Signature",
        "ARC-Authentication-Results",
        "ARC-Message-Signature",
        "ARC-Seal",
        "X-Originating-IP",
        "X-Mailer",
        "User-Agent",
        "MIME-Version",
        "Content-Type",
    ]
    for k in keys:
        vals = msg.get_all(k, failobj=[])
        if not vals:
            continue
        if k.lower() == "received":
            hdrs["Received"] = [decode_mime_header(v) for v in vals]
        else:
            if len(vals) == 1:
                hdrs[k] = decode_mime_header(vals[0])
            else:
                hdrs[k] = [decode_mime_header(v) for v in vals]
    return hdrs
