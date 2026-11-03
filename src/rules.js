// Detection rules. Token rules adapted from gitleaks (MIT); India rules from
// Microsoft Presidio India recognizers (MIT). Pattern hits on weak formats
// count only when a keyword sits nearby (see scripts/replay findings: bare
// 12-digit and 10-digit patterns are ~100% false positives in agent logs).

const D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];

export function verhoeff(digits) {
  let c = 0;
  for (let i = 0; i < digits.length; i++) c = D[c][P[i % 8][+digits[digits.length - 1 - i]]];
  return c === 0;
}

const digitsOnly = (s) => s.replace(/\D/g, "");

// keyword: regex that must appear within KEYWORD_WINDOW chars before or after.
// null keyword = format is distinctive enough on its own.
export const RULES = [
  // India
  { id: "aadhaar", kind: "pii", re: /(?<![\w-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\w-])/g,
    check: (v) => verhoeff(digitsOnly(v)), keyword: /aadhaa?r|uidai|\buid\b|आधार/i },
  { id: "pan", kind: "pii", re: /\b[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]\b/g,
    keyword: /\bpan\b|permanent account|income ?tax|\bitr\b/i },
  { id: "ifsc", kind: "pii", re: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g, keyword: /ifsc|bank|branch|neft|imps|rtgs/i },
  { id: "in_phone", kind: "pii", re: /(?<![\w.+-])(?:\+91[ -]?)?[6-9]\d{4}[ -]?\d{5}(?![\w.-])/g,
    keyword: /phone|mobile|whatsapp|\bcall\b|contact|\btel\b|\+91|\bmob\b/i },
  { id: "upi", kind: "pii", re: /\b[\w.-]{2,}@(?:ok(?:axis|hdfcbank|icici|sbi)|ybl|paytm|upi|ibl|axl|apl)\b/gi, keyword: null },
  { id: "passport_in", kind: "pii", re: /\b[A-PR-WY][1-9]\d{6}\b/g, keyword: /passport/i },
  // Tokens (gitleaks-derived)
  { id: "anthropic_key", kind: "secret", re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g, keyword: null },
  { id: "openrouter_key", kind: "secret", re: /\bsk-or-v1-[a-f0-9]{32,}/g, keyword: null },
  { id: "openai_key", kind: "secret", re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/g, keyword: null },
  { id: "github_token", kind: "secret", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/g, keyword: null },
  { id: "aws_access_key", kind: "secret", re: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g, keyword: null },
  { id: "slack_token", kind: "secret", re: /\bxox[abpors]-[A-Za-z0-9-]{10,}/g, keyword: null },
  { id: "google_api_key", kind: "secret", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, keyword: null },
  { id: "stripe_key", kind: "secret", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}/g, keyword: null },
  { id: "jwt", kind: "secret", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, keyword: null },
  { id: "private_key", kind: "secret", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, keyword: null },
];

export const KEYWORD_WINDOW = 48;
