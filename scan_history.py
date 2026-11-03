#!/usr/bin/env python3
"""Count PII/secret pattern hits in existing agent logs. Prints counts only, never values."""
import collections, glob, json, os, re, sqlite3, sys

H = os.path.expanduser
VERHOEFF_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
VERHOEFF_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
def verhoeff_ok(s):
    c = 0
    for i, ch in enumerate(reversed(s)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(ch)]]
    return c == 0

# Rules adapted from gitleaks (MIT) and Presidio India recognizers (MIT).
RULES = {
    "aadhaar":        (re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)"), lambda m: verhoeff_ok(re.sub(r"\D", "", m))),
    "pan":            (re.compile(r"\b[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]\b"), None),
    "ifsc":           (re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), None),
    "in_phone":       (re.compile(r"(?<![\d.])(?:\+91[ -]?)?[6-9]\d{9}(?![\d.])"), None),
    "email":          (re.compile(r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b", re.I), None),
    "upi":            (re.compile(r"\b[\w.-]{2,}@(?:ok(?:axis|hdfcbank|icici|sbi)|ybl|paytm|upi|ibl|axl)\b", re.I), None),
    "openai_key":     (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"), None),
    "anthropic_key":  (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), None),
    "openrouter_key": (re.compile(r"\bsk-or-v1-[a-f0-9]{20,}"), None),
    "github_token":   (re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}"), None),
    "aws_access_key": (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), None),
    "slack_token":    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), None),
    "google_api_key": (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), None),
    "jwt":            (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), None),
    "private_key":    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), None),
    "password_kv":    (re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S{6,}"), None),
}

def scan(text, counts, uniq):
    for name, (rx, check) in RULES.items():
        for m in rx.finditer(text):
            v = m.group(0)
            if check and not check(v):
                continue
            counts[name] += 1
            uniq[name].add(hash(v))

def report(label, counts, uniq, files):
    print(f"\n== {label} ({files} files/rows)")
    for k in RULES:
        if counts[k]:
            print(f"  {k:15} hits={counts[k]:6}  distinct={len(uniq[k]):5}")

def run(label, items):
    counts, uniq, n = collections.Counter(), collections.defaultdict(set), 0
    for text in items:
        n += 1
        scan(text, counts, uniq)
    report(label, counts, uniq, n)

def files(pattern):
    for f in glob.glob(H(pattern), recursive=True):
        try:
            yield open(f, errors="replace").read()
        except OSError:
            pass

def rows(db, sql):
    c = sqlite3.connect(f"file:{H(db)}?mode=ro", uri=True)
    for (d,) in c.execute(sql):
        yield d or ""

if __name__ == "__main__":
    run("Claude transcripts ~/.claude/projects", files("~/.claude/projects/**/*.jsonl"))
    run("Codex sessions ~/.codex/sessions", files("~/.codex/sessions/**/*"))
    run("9Router request log (requestDetails)", rows("~/.9router/db/data.sqlite", "select data from requestDetails"))
    run("T3 turn items (statev2)", rows("~/.t3/userdata/statev2.sqlite", "select payload_json from orchestration_v2_projection_turn_items"))
