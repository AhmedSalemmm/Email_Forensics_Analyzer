import os
import subprocess
from .utils import safe_mkdir, sha256_bytes, md5_bytes, which

def is_attachment(part) -> bool:
    cd = part.get_content_disposition()
    if cd == "attachment":
        return True
    filename = part.get_filename()
    return bool(filename)

def sanitize_filename(name: str) -> str:
    if not name:
        return "attachment.bin"
    # basic safe filename
    keep = []
    for ch in name:
        if ch.isalnum() or ch in "._-()[] ":
            keep.append(ch)
        else:
            keep.append("_")
    out = "".join(keep).strip()
    return out[:200] if out else "attachment.bin"

def exiftool_metadata(path: str):
    """
    Optional: returns a compact JSON-like dict from exiftool if installed.
    """
    if not which("exiftool"):
        return None
    try:
        # -j = JSON output, -n = numeric where possible
        res = subprocess.run(["exiftool", "-j", "-n", path], capture_output=True, text=True, check=False)
        if res.returncode != 0:
            return None
        import json
        data = json.loads(res.stdout)
        if isinstance(data, list) and data:
            # remove very large fields
            d = dict(data[0])
            for k in list(d.keys()):
                if isinstance(d[k], str) and len(d[k]) > 5000:
                    d[k] = d[k][:5000] + "...(truncated)"
            return d
        return None
    except Exception:
        return None

def extract_attachments(msg, out_dir: str, msg_tag: str):
    """
    Extract attachments from a message into out_dir/attachments/<msg_tag>/.
    Returns list of dict records for attachments_report.csv.
    """
    att_root = os.path.join(out_dir, "attachments", msg_tag)
    safe_mkdir(att_root)

    records = []
    idx = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        if not is_attachment(part):
            continue

        idx += 1
        filename = sanitize_filename(part.get_filename() or f"attachment_{idx}")
        ctype = part.get_content_type()
        payload = part.get_payload(decode=True) or b""
        size = len(payload)

        save_path = os.path.join(att_root, filename)
        # avoid overwrite collisions
        if os.path.exists(save_path):
            base, ext = os.path.splitext(filename)
            save_path = os.path.join(att_root, f"{base}_{idx}{ext}")

        with open(save_path, "wb") as f:
            f.write(payload)

        rec = {
            "message_tag": msg_tag,
            "filename": os.path.basename(save_path),
            "path": os.path.relpath(save_path, out_dir),
            "content_type": ctype,
            "size_bytes": size,
            "md5": md5_bytes(payload),
            "sha256": sha256_bytes(payload),
        }

        meta = exiftool_metadata(save_path)
        if meta:
            # keep a small subset to keep CSV readable
            for k in ["FileType", "MIMEType", "Creator", "Producer", "CreateDate", "ModifyDate", "Author", "Title"]:
                if k in meta:
                    rec[f"exif_{k}"] = str(meta[k])
        records.append(rec)

    return records
