#!/usr/bin/env python3
"""Generate fake OCR fixtures. Requires Chrome and ffmpeg."""
import html
import json
import random
import string
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "test/fixtures/ocr-corpus"
FFMPEG = "ffmpeg"
random.seed(17591)


def chars(alphabet, count):
    return "".join(random.choices(alphabet, k=count))


def aadhaar():
    d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
    p = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
    prefix = "23456789123"
    def valid(value):
        c = 0
        for i, digit in enumerate(reversed(value)):
            c = d[c][p[i % 8][int(digit)]]
        return c == 0
    value = next(prefix + str(n) for n in range(10) if valid(prefix + str(n)))
    assert valid(value)
    return " ".join((value[:4], value[4:8], value[8:]))


def corpus():
    alpha = string.ascii_letters + string.digits
    token = lambda n: chars(alpha, n)
    return [
        ("01_env_terminal.png", "terminal", ["ANTHROPIC=sk-ant-api03-" + token(40), "OPENAI=sk-proj-" + token(40)], ["anthropic_key", "openai_key"]),
        ("02_form.png", "form", ["Name: Priya Sharma", "Email: priya@paperlane.test", "Mobile: 98765 43210", "PAN: ABCPD1234F"], ["email", "in_phone", "pan"]),
        ("03_editor.png", "editor", ["const access = 'ghp_" + token(36) + "';", "const aws = 'AKIA" + chars(string.ascii_uppercase + string.digits, 16) + "';"], ["github_token", "aws_access_key"]),
        ("04_small.png", "small", ["Aadhaar: " + aadhaar(), "Visa card: 4111 1111 1111 1111"], ["aadhaar", "credit_card"]),
        ("05_low_contrast.png", "low", ["IFSC: HDFC0001234", "UPI: priya@okhdfcbank"], ["ifsc", "upi"]),
        ("06_blue.png", "blue", ["SSN: 078-05-1120", "Passport: A1234567"], ["us_ssn", "passport_in"]),
        ("07_heading.png", "heading", ["Vehicle: KA01AB1234", "Driving licence: KA01 2020 1234567"], ["vehicle_in", "driving_license_in"]),
        ("08_table.png", "table", ["Public IP: 23.45.67.89", "Private IP: 192.168.12.34", "Email: ravi@paperlane.test", "Mobile: 98765 12340"], ["ip_address", "ip_private", "email", "in_phone"]),
        ("09_chat.png", "chat", ["Priya Sharma", "Contact: priya@paperlane.test", "UPI: priya@okaxis"], ["email", "upi"]),
        ("10_url.png", "url", ["postgres://reader:Q7mZ3nV8@db.paperlane.test:5432/catalog"], ["connection_string"]),
        ("11_jpeg.jpg", "form", ["Google key: AIza" + chars(alpha + "_-", 35), "Stripe: sk_live_" + token(24)], ["google_api_key", "stripe_key"]),
        ("12_retina.png", "retina", ["Slack: xoxb-" + token(20), "Router: sk-or-v1-" + chars(string.hexdigits[:16], 64)], ["slack_token", "openrouter_key"]),
        ("13_mobile.png", "mobile", ["Priya Sharma", "PAN: ABCPD1234F", "Mobile: 98765 43210"], ["pan", "in_phone"]),
        ("14_jwt.png", "terminal", ["Bearer eyJ" + token(15) + ".eyJ" + token(15) + "." + token(16)], ["jwt"]),
        ("15_private_key.png", "editor", ["-----BEGIN PRIVATE KEY-----", "Synthetic content omitted", "-----END PRIVATE KEY-----"], ["private_key"]),
        ("16_obfuscated.png", "form", ["Contact: priya (at) paperlane (dot) test", "Bank IFSC: HDFC0001234"], ["email_obfuscated", "ifsc"]),
        ("17_assigned.png", "terminal", ["password=" + token(24)], ["assigned_secret"]),
        ("18_clean_code.png", "editor", ["const total = items.length;", "const ready = total > 3;", "return ready;"], []),
        ("19_clean_dashboard.png", "table", ["Visitors: 1248", "Orders: 73", "Revenue: 4062", "Uptime: 99.9%"], []),
        ("20_clean_prose.png", "form", ["Release version 2.14.3", "Meeting: 2026-11-05 at 14:30", "See you @ home. Call me at 5 pm."], []),
        ("21_clean_placeholder.png", "chat", ["Previous redaction", "{{pii:private_key#caa9fb}}", "No private key is shown."], []),
        ("22_clean_url.png", "url", ["https://paperlane.test/catalog?view=grid"], []),
        ("23_finance.png", "form", ["Visa card: 4111 1111 1111 1111", "Bank IFSC: HDFC0001234"], ["credit_card", "ifsc"]),
        ("24_ids.png", "form", ["Passport: A1234567", "SSN: 078-05-1120"], ["passport_in", "us_ssn"]),
    ]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    # Only delete generated images, never other fixture files.
    for pattern in ("*.png", "*.jpg"):
        for old in OUT.glob(pattern):
            old.unlink()
    labels = {}
    styles = {
        "terminal": "background:#171b23;color:#e6edf3;font:18px monospace",
        "form": "background:#fff;color:#20242a;font:18px Arial,sans-serif",
        "editor": "background:#20242e;color:#e3e7ed;font:14px monospace",
        "small": "background:#fff;color:#111;font:11px Arial,sans-serif",
        "low": "background:#d9d9d9;color:#777;font:20px Arial,sans-serif",
        "blue": "background:#1658aa;color:white;font:20px Arial,sans-serif",
        "heading": "background:#fff;color:#111;font:24px Arial,sans-serif",
        "table": "background:#f5f8fa;color:#172331;font:18px Arial,sans-serif",
        "chat": "background:#eef3f9;color:#152331;font:18px Arial,sans-serif",
        "url": "background:#eff2f6;color:#111;font:16px monospace",
        "retina": "background:#fff;color:#111;font:16px monospace",
        "mobile": "background:#fff;color:#111;font:17px Arial,sans-serif",
    }
    with tempfile.TemporaryDirectory(prefix="pii-ocr-corpus-") as tmp:
        tmp = Path(tmp)
        for index, (name, style, lines, ids) in enumerate(corpus()):
            labels[name] = ids
            width, height = (390, 300) if style == "mobile" else (1100, 300)
            layout = "display:grid;grid-template-columns:1fr 1fr;gap:14px" if style == "table" else ""
            item = "padding:12px;border-radius:12px;background:#fff;margin-bottom:8px" if style == "chat" else "padding:8px 0;white-space:pre"
            content = "".join(f'<div style="{item}">{html.escape(line)}</div>' for line in lines)
            page = tmp / f"{index}.html"
            page.write_text(f'<!doctype html><meta charset="utf-8"><style>body{{margin:0;padding:24px;{styles[style]}}}</style><main style="{layout}">{content}</main>', encoding="utf-8")
            screenshot = tmp / "source.png" if name.endswith(".jpg") else OUT / name
            cmd = ["google-chrome", "--headless=new", "--disable-gpu", "--no-sandbox", f"--user-data-dir={tmp / 'chrome'}", "--hide-scrollbars", f"--window-size={width},{height}", f"--screenshot={screenshot}"]
            if style == "retina":
                cmd.append("--force-device-scale-factor=2")
            subprocess.run(cmd + [page.as_uri()], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if name.endswith(".jpg"):
                subprocess.run([FFMPEG, "-v", "error", "-y", "-i", str(screenshot), "-q:v", "8", str(OUT / name)], check=True)
    (OUT / "labels.json").write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")
    assert len(labels) == 24 and sum((OUT / name).stat().st_size for name in labels) < 1_500_000


if __name__ == "__main__":
    main()
