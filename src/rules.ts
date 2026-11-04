// Detection rules. Token rules adapted from gitleaks (MIT); India rules from
// Microsoft Presidio India recognizers (MIT). Pattern hits on weak formats
// count only when a keyword sits nearby (see pii-guard replay findings: bare
// 12-digit and 10-digit patterns are ~100% false positives in agent logs).

const D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];

export function verhoeff(digits: string): boolean {
  let c = 0;
  for (let i = 0; i < digits.length; i++) c = D[c][P[i % 8][+digits[digits.length - 1 - i]]];
  return c === 0;
}

const digitsOnly = (s: string) => s.replace(/\D/g, "");

function luhn(value: string): boolean {
  const digits = digitsOnly(value);
  if (digits.length < 13 || digits.length > 19 || /^(.)\1+$/.test(digits)) return false;
  let sum = 0;
  for (let i = digits.length - 1, double = false; i >= 0; i--, double = !double) {
    let digit = +digits[i];
    if (double) { digit *= 2; if (digit > 9) digit -= 9; }
    sum += digit;
  }
  return sum % 10 === 0;
}

// Placeholder and bot addresses that are never personal data.
const EMAIL_IGNORE = /^(?:no-?reply|do-?not-?reply|git)@|@(?:[\w-]+\.)*example\.(?:com|org|net)$|@users\.noreply\.github\.com$|\.(?:internal|local|localhost|invalid)$/i;

// Private, loopback, link-local, CGNAT, documentation and well-known public DNS addresses.
function publicIp(v: string): boolean {
  const o = v.split(".").map(Number);
  if (o.some(n => n > 255)) return false;
  const [a, b, c, d] = o;
  if (d === 0 || d === 255) return false; // network or broadcast address, usually a CIDR or mask
  if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) return false;
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return false;
  return !["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"].includes(v);
}

function privateIp(v: string): boolean {
  const o = v.split(".").map(Number);
  if (o.some(n => n > 255)) return false;
  const [a, b, , d] = o;
  // ponytail: .0/.255 skipped as CIDR/broadcast noise; misses rare x.y.z.0 hosts in a /16. Read the prefix length if that matters.
  if (d === 0 || d === 255) return false;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

// Shared by ip_address and ip_private so the version-string guards cannot drift. matchAll clones the regex.
const IPV4 = /(?<![\w.])(?<!\b(?:v|ver|version|release|build)[\s:=@-]{0,3})(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)(?!\.\w)/g;

// `token: string`, `password: z.string()` and env lookups are code, not secrets.
// Template text such as YOUR_DB_PASSWORD, masked values (gho_****) and elided ones (sk-proj-...) are not secrets.
const PLACEHOLDER = /your[-_]|[-_]here\b|change-?me|placeholder|dummy|not[-_]a[-_]real|example|\*{3}|\.\.\.|…|\$\{|\}\}|[^\x20-\x7e]/i;
const assignedSecret = (v: string) => !/^(?:-?[$<[{\\*~/.]|process\.env|os\.environ|env\.|import\.meta|self\.|this\.)/.test(v)
  && !PLACEHOLDER.test(v) && !/^\d+$/.test(v)
  // Member access such as `request.headers.get` or `creds.accessToken` is code.
  && !/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+(?:\(\))?$/.test(v)
  && (/\d/.test(v) && /[A-Za-z]/.test(v) || v.length >= 16);

export interface Rule {
  id: string;
  kind: "pii" | "secret";
  re: RegExp;
  keyword: RegExp | null;
  check?: (v: string) => boolean;
}

// keyword: regex that must appear within KEYWORD_WINDOW chars before or after.
// null keyword = format is distinctive enough on its own.
export const RULES: Rule[] = [
  { id: "email", kind: "pii", re: /(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.[A-Za-z]{2,63}\b/g, check: v => !EMAIL_IGNORE.test(v), keyword: null },
  // "name (at) host dot com", "name [at] host [dot] com", "name%40host.com"
  { id: "email_obfuscated", kind: "pii", re: /(?<![\w.+-])[A-Za-z0-9._+-]{1,64}(?:\s*[([{]\s*at\s*[)\]}]\s*|%40)[A-Za-z0-9-]+(?:(?:\.|\s*[([{]\s*dot\s*[)\]}]\s*|\s+dot\s+)[A-Za-z0-9-]+)*(?:\.|\s*[([{]\s*dot\s*[)\]}]\s*|\s+dot\s+)[A-Za-z]{2,63}\b/gi, keyword: null },
  { id: "us_ssn", kind: "pii", re: /(?<![\w-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\w-])/g, keyword: /\bssn\b|social security/i },
  { id: "ip_address", kind: "pii", re: IPV4, check: publicIp, keyword: null },
  { id: "ip_private", kind: "pii", re: IPV4, check: privateIp, keyword: null },
  { id: "credit_card", kind: "pii", re: /(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])/g, check: luhn, keyword: /card|visa|mastercard|amex/i },
  // India
  { id: "vehicle_in", kind: "pii", re: /\b(?:AP|AR|AS|BR|CG|CH|DD|DL|DN|GA|GJ|HP|HR|JH|JK|KA|KL|LA|LD|MH|ML|MN|MP|MZ|NL|OD|OR|PB|PY|RJ|SK|TN|TR|TS|TG|UK|UP|UT|WB)[ -]?\d{1,2}[ -]?[A-Z]{1,3}[ -]?\d{1,4}\b|\b\d{2}[ -]?BH[ -]?\d{4}[ -]?[A-Z]{1,2}\b/g, keyword: /reg(?:istration|n)?\b|vehicle|number plate|motorcycle|bike/i },
  { id: "driving_license_in", kind: "pii", re: /\b[A-Z]{2}[ -]?\d{2}[ -]?(?:19|20)\d{2}[ -]?\d{7}\b/g, keyword: /licen[cs]e|driving|\bdl\b/i },
  { id: "aadhaar", kind: "pii", re: /(?<![\w-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\w-])/g,
    check: (v: string) => verhoeff(digitsOnly(v)), keyword: /aadhaa?r|uidai|\buid\b|आधार/i },
  { id: "pan", kind: "pii", re: /\b[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]\b/g,
    keyword: /\bpan\b|permanent account|income ?tax|\bitr\b/i },
  { id: "ifsc", kind: "pii", re: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g, keyword: /ifsc|bank|branch|neft|imps|rtgs/i },
  { id: "in_phone", kind: "pii", re: /(?<![\w.+-])(?:\+91[ -]?)?[6-9]\d{4}[ -]?\d{5}(?![\w.-])/g,
    keyword: /phone|mobile|whatsapp|\bcall\b|contact|\btel\b|\+91|\bmob\b/i },
  { id: "upi", kind: "pii", re: /(?<![\w.-])[\w.-]{2,64}@(?:ok(?:axis|hdfcbank|icici|sbi)|ybl|paytm|upi|ibl|axl|apl)\b/gi, keyword: null },
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
  { id: "connection_string", kind: "secret", re: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@'"]+:[^\s@/'"]+@[^\s/?#'"`]+/gi, check: v => !/:\/\/[^:]*:(?:pass(?:word)?|secret|\*+|x+)@/i.test(v) && !PLACEHOLDER.test(v.replace(/^[^:]+:\/\//, "")), keyword: null },
  // Value only, so redaction keeps the key name readable.
  { id: "assigned_secret", kind: "secret", re: /(?<=(?<![A-Za-z0-9])(?:password|passwd|pwd|secret|client_secret|api[_-]?key|token|access[_-]?token|auth[_-]?token)["']?\s{0,8}[:=]\s{0,8}["']?)[^\s"'`&,;()\\]{8,}/gi, check: assignedSecret, keyword: null },
  { id: "private_key", kind: "secret", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, keyword: null },
];

export const KEYWORD_WINDOW = 48;
