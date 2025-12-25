import os
import sys
import csv
import glob
import tempfile
import subprocess
from argparse import ArgumentParser

from .utils import safe_mkdir, write_jsonl, which
from .parser import iter_mbox_messages, extract_core_fields, extract_headers_structured, message_fingerprint
from .spoofing import indicator_rules
from .attachments import extract_attachments
from .interactions import build_interactions, edges_to_rows


def find_mbox_files(input_path: str):
    if os.path.isdir(input_path):
        # Accept directory of mbox files
        cands = []
        for ext in ("*.mbox", "*.mbx", "*.mbox.txt", "*.txt", "*.mail"):
            cands.extend(glob.glob(os.path.join(input_path, ext)))
        # also include files with no extension (common in Thunderbird exports)
        for p in glob.glob(os.path.join(input_path, "*")):
            if os.path.isfile(p) and "." not in os.path.basename(p):
                cands.append(p)
        return sorted(list(dict.fromkeys(cands)))
    return [input_path]


def pst_to_mbox(pst_path: str, out_dir: str):
    """
    Convert PST -> MBOX using readpst (pst-utils / libpst).
    Produces a directory tree of mbox files.
    """
    if not which("readpst"):
        raise RuntimeError("readpst not found. Install: sudo apt install pst-utils")
    safe_mkdir(out_dir)
    # -M = output mboxrd, -D = include deleted items? we keep default off.
    # -o output directory
    cmd = ["readpst", "-M", "-o", out_dir, pst_path]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"readpst failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
    # readpst may generate many *.mbox files
    mboxes = []
    for root, _, files in os.walk(out_dir):
        for fn in files:
            if fn.lower().endswith((".mbox", ".mbx")) or fn.lower() in {"mbox"}:
                mboxes.append(os.path.join(root, fn))
    # also accept any files with typical mailbox naming
    if not mboxes:
        for root, _, files in os.walk(out_dir):
            for fn in files:
                if fn.lower().endswith(".txt") or fn.lower().endswith(".mboxrd"):
                    mboxes.append(os.path.join(root, fn))
    return sorted(mboxes)


def write_csv(path: str, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def analyze(input_path: str, out_dir: str, filter_from: str = "", filter_subject: str = "", max_emails: int = 0):
    safe_mkdir(out_dir)

    # Determine mbox list
    mbox_files = []
    tmp_dir = None
    if input_path.lower().endswith(".pst"):
        tmp_dir = tempfile.mkdtemp(prefix="pst2mbox_")
        mbox_files = pst_to_mbox(input_path, tmp_dir)
    else:
        mbox_files = find_mbox_files(input_path)

    if not mbox_files:
        raise RuntimeError("No mailbox files found to parse.")

    core_rows = []
    headers_rows = []
    spoof_rows = []
    att_rows = []

    total = 0
    for mbox_path in mbox_files:
        for msg in iter_mbox_messages(mbox_path):
            total += 1
            if max_emails and len(core_rows) >= max_emails:
                break

            core = extract_core_fields(msg)

            if filter_from:
                if filter_from.lower() not in (core.get("from_raw","").lower() + " " + core.get("sender_email","").lower()):
                    continue
            if filter_subject:
                if filter_subject.lower() not in (core.get("subject","").lower()):
                    continue

            tag = message_fingerprint(msg)
            core["source_mailbox"] = os.path.basename(mbox_path)
            core["message_tag"] = tag

            hdrs = extract_headers_structured(msg)
            headers_rows.append({"message_tag": tag, "headers": hdrs})

            indicators, details, score, risk = indicator_rules(core, msg)
            spoof = {
                "message_tag": tag,
                "source_mailbox": os.path.basename(mbox_path),
                "date_iso": core.get("date_iso",""),
                "sender_email": core.get("sender_email",""),
                "sender_domain": core.get("sender_domain",""),
                "subject": core.get("subject",""),
                "risk_score": score,
                "risk_level": risk,
            }
            # Flatten indicator booleans
            for k, v in indicators.items():
                spoof[k] = int(bool(v))
            # Keep short explanations
            for k, v in details.items():
                spoof[f"detail_{k}"] = v
            spoof_rows.append(spoof)

            # Attachments
            att_rows.extend(extract_attachments(msg, out_dir, tag))

            core_rows.append(core)

        if max_emails and len(core_rows) >= max_emails:
            break

    # Write outputs
    emails_fields = [
        "message_tag","source_mailbox","date_iso","sender_email","sender_domain",
        "to_raw","cc_raw","subject","message_id","return_path","reply_to"
    ]
    write_csv(os.path.join(out_dir, "emails.csv"), emails_fields, core_rows)

    # JSONL headers (headers can be nested -> JSONL)
    write_jsonl(os.path.join(out_dir, "headers.jsonl"), headers_rows)

    # Spoofing report fields (dynamic)
    base_fields = ["message_tag","source_mailbox","date_iso","sender_email","sender_domain","subject","risk_score","risk_level"]
    # collect other keys
    extra_keys = set()
    for r in spoof_rows:
        for k in r.keys():
            if k not in base_fields:
                extra_keys.add(k)
    spoof_fields = base_fields + sorted(extra_keys)
    write_csv(os.path.join(out_dir, "spoofing_report.csv"), spoof_fields, spoof_rows)

    # Campaign clustering (simple)
    campaigns = {}
    for r in core_rows:
        key = (r.get("subject_norm",""), r.get("sender_domain",""))
        if key not in campaigns:
            campaigns[key] = {"subject_norm": key[0], "sender_domain": key[1], "count": 0, "first_seen": "", "last_seen": "", "example_subject": r.get("subject","")}
        campaigns[key]["count"] += 1
        dt = r.get("date_iso","")
        if dt:
            if not campaigns[key]["first_seen"] or dt < campaigns[key]["first_seen"]:
                campaigns[key]["first_seen"] = dt
            if not campaigns[key]["last_seen"] or dt > campaigns[key]["last_seen"]:
                campaigns[key]["last_seen"] = dt
    campaigns_rows = list(campaigns.values())
    campaigns_rows.sort(key=lambda x: (-x["count"], x["sender_domain"], x["subject_norm"]))
    write_csv(os.path.join(out_dir, "campaigns.csv"), ["subject_norm","sender_domain","count","first_seen","last_seen","example_subject"], campaigns_rows)

    # Interactions
    edges = build_interactions(core_rows)
    edge_rows = edges_to_rows(edges)
    write_csv(os.path.join(out_dir, "interactions.csv"), ["sender","recipient","count","first_seen","last_seen"], edge_rows)

    # Attachments report
    if att_rows:
        # collect fields dynamically (some exiftool fields optional)
        base = ["message_tag","filename","path","content_type","size_bytes","md5","sha256"]
        extra = set()
        for a in att_rows:
            for k in a.keys():
                if k not in base:
                    extra.add(k)
        fields = base + sorted(extra)
        write_csv(os.path.join(out_dir, "attachments_report.csv"), fields, att_rows)
    else:
        write_csv(os.path.join(out_dir, "attachments_report.csv"), ["message_tag","filename","path","content_type","size_bytes","md5","sha256"], [])

    # Console summary
    print(f"[+] Parsed mailboxes: {len(mbox_files)} file(s)")
    print(f"[+] Emails analyzed: {len(core_rows)} (raw scanned: {total})")
    print(f"[+] Attachments extracted: {len(att_rows)}")
    print(f"[+] Outputs written to: {out_dir}")

    # Cleanup temp conversion dir
    if tmp_dir:
        # Keep it by default? We remove to be tidy (inputs stay intact).
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)


def main(argv=None):
    argv = argv or sys.argv[1:]
    ap = ArgumentParser(prog="email_forensics_analyzer", description="Email Forensics Analyzer (MBOX/PST).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_an = sub.add_parser("analyze", help="Analyze an MBOX mailbox (or PST via readpst).")
    ap_an.add_argument("--input", required=True, help="Path to .mbox file, directory of mbox files, or .pst file.")
    ap_an.add_argument("--out", required=True, help="Output directory.")
    ap_an.add_argument("--filter-from", default="", help="Only keep emails whose From contains this substring.")
    ap_an.add_argument("--filter-subject", default="", help="Only keep emails whose Subject contains this substring.")
    ap_an.add_argument("--max-emails", type=int, default=0, help="Max emails to analyze (0 = no limit).")

    args = ap.parse_args(argv)
    if args.cmd == "analyze":
        analyze(
            input_path=args.input,
            out_dir=args.out,
            filter_from=args.filter_from,
            filter_subject=args.filter_subject,
            max_emails=args.max_emails,
        )

if __name__ == "__main__":
    main()
