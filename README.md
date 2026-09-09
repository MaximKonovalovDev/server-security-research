# server-security-research

Defensive game-server hardening guides plus a 20-point pre-playtest checklist. Docs only, no attack tools.

Origin: notes from running a private Flax multiplayer lab, cleaned for public use. Part of flax-game-studio game-security work.

## Why

Most small multiplayer games ship with the client in charge. That is how speed hacks, teleport hacks, duped items, and dead economies happen. Fixing it after launch costs far more than building it right from day one.

This repo holds the defender's side of that work: server authority, signed packets, strict parsing, rate limits, and an ops routine. It proves the checklist, not the weapon.

## What it does

Six guides, one checklist, two reports. All defensive, all plain text.

- `docs/SECURITY-BY-DESIGN.md` — five day-one rules: server authority, per-session integrity, protocol design, telemetry, free ops steps.
- `docs/SERVER-SECURITY.md` — server hardening plan for a Flax 1.12 ENet UDP server: P0/P1/P2 order, auth, rate-limit numbers, monitoring.
- `docs/SECURED-SERVER.md` — hosted-build blueprint: edge proxy, process split, key rotation, phased build, scaling notes.
- `docs/MCP-SECURITY.md` — MCP endpoint hardening: auth tokens, origin checks, permission tiers, supply-chain hygiene.
- `docs/BUILD-GAME-SERVER.md` — short defense cookbook: authority, hostile-input protocol, budgets, graded response.
- `docs/AI-SENTINEL.md` — watchdog spec: threshold to anomaly to supervised tiers, advisory only, false-positive gate.
- `HARDENING-CHECKLIST.md` — 20-point list to run before any playtest.
- `reports/FINDINGS-001-initial-audit.md` — sample audit format with real finding IDs.
- `reports/RESEARCH-002-killed-by-cheaters-ai-threats.md` — threat research notes: games hurt by cheaters, AI-era model.

What is NOT here: attack playbooks, exploits, payloads, scanners, fuzzers, dissectors, rogue clients, or bypass techniques. Those stay private. This repo is defense and audit only.

## Quick start

```sh
git clone https://github.com/MaximKonovalovDev/server-security-research.git
cd server-security-research
ls docs
ls reports
cat HARDENING-CHECKLIST.md
```

Then read in this order: `docs/SECURITY-BY-DESIGN.md`, `docs/SERVER-SECURITY.md`, `HARDENING-CHECKLIST.md`. The rest is reference.

## Demo + proof

Measured in this repo, no hidden steps:

- Checklist: 20 checks plus one sign-and-date line in `HARDENING-CHECKLIST.md`.
- Guides: 6 docs files, about 1070 lines total.
- Reports: 2 files, about 180 lines total.
- Secret scan: clean, no tokens or private keys found in docs, reports, or checklist.
- Attack tools: none. No exploits, payloads, scanners, or bypass code exist here.

To verify yourself:

```sh
grep -c "^- \[ \]" HARDENING-CHECKLIST.md
wc -l docs/*.md reports/*.md
grep -rE "sk-ant-|ghp_|gho_|AKIA|PRIVATE KEY" docs reports HARDENING-CHECKLIST.md || echo "clean"
```

## Project structure

```text
server-security-research/
  README.md
  LICENSE
  HARDENING-CHECKLIST.md
  docs/
    SECURITY-BY-DESIGN.md
    SERVER-SECURITY.md
    SECURED-SERVER.md
    MCP-SECURITY.md
    BUILD-GAME-SERVER.md
    AI-SENTINEL.md
  reports/
    FINDINGS-001-initial-audit.md
    RESEARCH-002-killed-by-cheaters-ai-threats.md
```

## License

MIT. See `LICENSE`.

## Author

Maxim Konovalov, Haifa. Part of flax-game-studio game-security work.
