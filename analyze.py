#!/usr/bin/env python3
"""Send a log file to the AI incident analyzer and print a short human-readable report.

Usage:
    export API_TOKEN=<token you were given>
    python3 analyze.py [it_task_log.log] [-o report.md] [--json]

Python 3.8+, standard library only.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API_URL = "https://incident-ai.trussardiops.click/analyze"
MAX_LOG_BYTES = 150 * 1024
SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def bullets(items):
    return "\n".join(f"- {i}" for i in items) or "- (none)"


SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def services_table(r):
    """One row per service: worst severity, role (cause/symptom) and the findings it appears in."""
    rows = {}
    for n, f in enumerate(r.get("key_findings", []), 1):
        for svc in f.get("services", []):
            row = rows.setdefault(svc, {"sev": "low", "kinds": set(), "ids": []})
            if SEV_RANK.get(f.get("severity"), 3) < SEV_RANK[row["sev"]]:
                row["sev"] = f.get("severity")
            row["kinds"].add(f.get("kind", ""))
            row["ids"].append(f"#{n}")
    out = ["| Service | Severity | Role | Findings |", "|---|---|---|---|"]
    for svc, row in sorted(rows.items(), key=lambda kv: SEV_RANK[kv[1]["sev"]]):
        role = "cause" if "cause" in row["kinds"] else "symptom"
        out.append(f"| `{svc}` | {SEV_ICON.get(row['sev'], '')} {row['sev']} | {role} | {', '.join(row['ids'])} |")
    return out


def tx_table(r):
    items = r.get("transactions_to_recheck", [])
    if not items:
        return ["No failed or unclear transactions found in the log."]
    out = ["| IDs | State in log | What to check |", "|---|---|---|"]
    for t in items:
        ids = "<br>".join(f"`{i}`" for i in t.get("ids", []))
        out.append(f"| {ids} | {t.get('state_in_log', '')} | {t.get('check', '')} |")
    return out


def render(r):
    sev = r.get("severity", "?")
    pc = r.get("probable_cause", {})
    imp = r.get("impact", {})
    out = [
        "# Incident report",
        "",
        f"**Severity:** {SEV_ICON.get(sev, '')} {sev.upper()}",
        "",
        "## Summary",
        "",
        r.get("summary", ""),
        "",
        "## Affected services",
        "",
        *services_table(r),
        "",
        "## Probable cause",
        "",
        f"{pc.get('most_likely', '')}",
        "",
        f"**Confidence:** {pc.get('confidence', '?')}",
    ]
    if pc.get("alternatives"):
        out += ["", "**Alternatives:**", "", bullets(pc["alternatives"])]
    out += ["", "## Key findings"]
    for n, f in enumerate(r.get("key_findings", []), 1):
        icon = SEV_ICON.get(f.get("severity"), "")
        out += [
            "",
            f"### {n}. {icon} {f.get('title', '')}",
            "",
            f"**Type:** {f.get('kind', '')} | **Severity:** {f.get('severity', '')}",
            "",
            f"**What happened:** {f.get('what_happened', '')}",
            "",
            "**Services:**",
            "",
            bullets(f"`{x}`" for x in f.get("services", [])),
            "",
            "**Evidence:**",
            "",
            "```",
            *f.get("evidence", []),
            "```",
        ]
    out += [
        "",
        "## Timeline", "", bullets(r.get("timeline", [])), "",
        "## Impact", "",
        "**Propagation:** " + imp.get("propagation", ""), "",
        "## Transactions to re-check", "",
        *tx_table(r), "",
        "## Uncertainty (cannot be determined from logs)", "", bullets(r.get("uncertainty", [])), "",
        "## Next steps", "", *[f"{i}. {s}" for i, s in enumerate(r.get("next_steps", []), 1)],
    ]
    return "\n".join(out) + "\n"


def call_api(token, log_text):
    req = urllib.request.Request(
        API_URL,
        data=json.dumps({"log": log_text}).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        hints = {401: "token invalid or expired", 403: "token invalid/expired or daily quota (20/day) used",
                 429: "rate limit (1 request/second) or daily quota exceeded", 413: "log too large"}
        body = e.read().decode(errors="replace")[:300]
        sys.exit(f"API error {e.code}: {hints.get(e.code, '')} {body}".strip())
    except urllib.error.URLError as e:
        sys.exit(f"Cannot reach {API_URL}: {e.reason}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("logfile", nargs="?", default="it_task_log.log")
    ap.add_argument("-o", "--output", default="report.md", help="report file (default: report.md)")
    ap.add_argument("--json", action="store_true", help="also save raw JSON next to the report")
    args = ap.parse_args()

    token = os.environ.get("API_TOKEN")
    if not token:
        sys.exit("Set API_TOKEN first:  export API_TOKEN=<token>")

    with open(args.logfile, encoding="utf-8", errors="replace") as fh:
        log_text = fh.read()
    size = len(log_text.encode())
    if size > MAX_LOG_BYTES:
        sys.exit(f"Log is {size // 1024} KB; limit is {MAX_LOG_BYTES // 1024} KB. Trim it (e.g. the incident window).")

    print(f"Analyzing {args.logfile} ({size // 1024} KB), takes ~20-30s...", file=sys.stderr)
    result = call_api(token, log_text)
    report = render(result)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)
    if args.json:
        with open(os.path.splitext(args.output)[0] + ".json", "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
    print(f"Report saved to {os.path.abspath(args.output)}", file=sys.stderr)


if __name__ == "__main__":
    main()
