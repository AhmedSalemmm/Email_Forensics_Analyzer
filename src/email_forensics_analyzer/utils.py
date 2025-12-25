import re
import os
import sys
import json
import hashlib
from email.header import decode_header
from email.utils import getaddresses, parsedate_to_datetime

def safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def md5_bytes(data: bytes) -> str:
    h = hashlib.md5()
    h.update(data)
    return h.hexdigest()

def decode_mime_header(value: str) -> str:
    if not value:
        return ""
    parts = []
    for frag, enc in decode_header(value):
        if isinstance(frag, bytes):
            try:
                parts.append(frag.decode(enc or "utf-8", errors="replace"))
            except Exception:
                parts.append(frag.decode("utf-8", errors="replace"))
        else:
            parts.append(str(frag))
    return "".join(parts).strip()

def normalize_subject(subject: str) -> str:
    s = decode_mime_header(subject or "")
    # Remove common prefixes repeatedly: Re:, Fwd:, FW:
    while True:
        s2 = re.sub(r"^\s*(re|fwd|fw)\s*:\s*", "", s, flags=re.I)
        if s2 == s:
            break
        s = s2
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s

def parse_email_date(date_str: str):
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str)
        # normalize aware->naive ISO for consistent CSV
        return dt
    except Exception:
        return None

def addr_list(header_value: str):
    # returns list of (name, email)
    if not header_value:
        return []
    decoded = decode_mime_header(header_value)
    return [(n.strip(), a.strip().lower()) for n, a in getaddresses([decoded]) if a]

def domain_of(addr: str) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.split("@", 1)[1].lower().strip()

def write_jsonl(path: str, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def which(cmd: str):
    from shutil import which as _which
    return _which(cmd)
