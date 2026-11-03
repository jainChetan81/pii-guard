# pii-guard

Detect known secrets and PII patterns in agent logs and summarize observe-mode events.
Runs with Bun or Node 26. No dependencies.

```sh
pii-guard known export --bw-json vault-export.json --out ~/.config/pii-guard/known.json
pii-guard replay --source claude,codex --since 7d
pii-guard report --since 24h
```

`known export` reads Bitwarden items or runs `bw list items` with `BW_SESSION`.
Use `BW_BIN` to override the binary. Use `--folder`, `--collection`, or `--org` to filter.
Repeat `--from-text FILE` for notes. With only text inputs, Bitwarden is not called.
The known list contains secrets. Protect it and its backups.

`replay` scans Claude, Codex, T3, and 9Router logs under your home directory.
Use `--home DIR` for another home, or `--stdin --label NAME` for JSONL input.
Use `--known FILE` to select a list, and `--context` for masked context shapes.
Use `--since 7d`, `--since 24h`, or `--since YYYY-MM-DD` to filter.
Reports go to `reports/replay-YYYYMMDD-HHMM.md` in the current directory.
`report` reads `~/.9router/pii-guard/events.jsonl`; override with `--events FILE`.

Commands never print matched values or raw surrounding text. Context masks alphanumerics.
The default known list is `~/.config/pii-guard/known.json`, mode 600.
New parent directories use mode 700. Reports use mode 600 in a mode 700 directory.
