# RESEARCH-002 — Games Destroyed by Cheaters + Web-Game Hacks + AI-Era Threat Model

Research compiled 2026-08-01. Two rounds of web research (general + Reddit round 3 pending).

## 1. The graveyard — games that died to cheaters

| Game | What hackers did | End | Source |
|---|---|---|---|
| The Cycle: Frontier (Yager) | Rampant aimbots/wallhacks in first months | **Devs officially said cheaters caused "irreparable damage"** and shut it down (2023) | gamedeveloper.com |
| APB: All Points Bulletin | Hackers dominated urban warfare | Shut 2010; later revived by another publisher | getgud.io |
| H1Z1: Just Survive | Aimbots, wallhacks | Shut Oct 2018 | getgud.io |
| Star Wars Galaxies | Bots + gold sellers, no enforcement | "plagued with bots... led to the game's downfall" | thegamer.com |
| LawBreakers | Cheating + toxicity, small base | Dead Sep 2018 | getgud.io |
| MAG (256p) | Cheats + server issues | Dead Jan 2014 | getgud.io |
| The Culling | Balancing + rampant cheating, 3 reboots failed | Closed Mar 2019 | getgud.io |
| Radical Heights | No anti-cheat at all | Dead + studio closed May 2018 | getgud.io |
| Dirty Bomb | Cheaters on declining base | Support ended 2019 | getgud.io |
| F.E.A.R. Online | Cheaters + technical issues from launch | Closed 2015 (1 year after release) | getgud.io |
| PlanetSide Arena | Small base + cheating | Dead in 5 months (Jan 2020) | getgud.io |
| Paragon | Griefing + balance, not solely cheating | Shut Apr 2018 | getgud.io |

**Pattern:** client trusted + weak/no anti-cheat + no server validation → legit players leave → revenue dies → shutdown.

## 2. RYL (Risk Your Life) — ryl.com.my deep dive

- **Background:** Developed/published by **Youxiland Digital (Malaysian studio)**; launched **Jan 5, 2005**, subscription model. ryl.com.my = official Malaysian portal. Huge in SEA (MY/ID/PH/TH/VN). Hardcore PvP (Human vs Ak'kan, open PK). (mmohuts.com, mmos.com)
- **Hack ecosystem (2005–2010):** RYL Multi-Hit 0.4 (2005, hit multiple times per attack); damage editing ("make weapons DMG as high as you want" — XUnleashed); item duping (UnknownCheats dupe threads since 2005); WPE Pro packet sniff/editing (Malwarebytes still flags it); GameGuard bypasses; macros/bots (farming/combat automation, e.g. Ap0dexMe0/RiskYourLife-Macros).
- **Why it worked:** early-2000s client-trusting architecture — damage/attack-rate/drops loosely validated or client-computed.
- **Death spiral:** PvP unplayable (multihit one-shots) + dupe-flooded economy → paying subs quit → revenue collapse → official shutdown ("the original server shutdown long ago because of hacking" — UnknownCheats). Server files leaked (RaGEZONE: versions 1753/2240/1756 + tutorials) → private servers with x10000 rates drained the rest. Nuance: r/MMORPG post-mortem says RYL2 also self-harmed by switching F2P+cash-shop → subscription (multifactorial death, hacking was the enabler).
- **Aftermath:** Youxiland declared private servers illegal (2016), relaunched as ROW "Return of Warrior" (Mar 26, 2017) — also died. RYL survives only via private servers (MY groups still active 2026: r/RiskYourLife, Facebook).
- **Research leads:** ThatNotEasy/RYL (GitHub) — ongoing RYL2 security-research project (protocol/DB/RE); XUnleashed RYL hacks archive; RaGEZONE RYL section (netbug, GMhack, party bug, skill bug, anti-debugger discussions — the server-side holes).

## 3. Web/browser games destroyed

| Game | How | Status |
|---|---|---|
| Roblox | Aug 2016 breach: 50K+ users (email/IP/username/purchases/Robux) leaked from a test server (HIBP). Exploit ecosystem: Lua executors (JJSploit 69M+ dl, Krnl 37M+, Solara), teleport/fly/ESP scripts, lagswitch. HackerOne scope: "data model vulnerabilities used by exploiters to crash game servers ARE in scope" | Alive (BYFron kernel AC) but permanent exploit war |
| Krunker.io | Tampermonkey userscripts + console JS: aimbot, ESP, tracers, fly, speed. Public GitHub exploit suites (WebGL2/GLSL) | Cheat-riddled; vote-kick as "anti-cheat" |
| .io genre (Diep/Kirka/1v1.lol/Venge/Gartic) | JS hacks: ESP, aimbot, godmode, autofarm bots | Widespread (cheater.ninja catalogs) |
| Growtopia | Hackers + exploit economy destroyed the game; devs sold it to Ubisoft | Sold after collapse |

**Web-game lesson:** client JS is fully exposed (devtools); server-side validation is everything.

## 4. AI-era threat model (2026)

### What AI changed
1. **Cheat development cost → ~zero.** LLMs write memory hacks, packet tools, JS injects (GitHub community discussion 2026: "AI reduced the cost, time, and knowledge required").
2. **Computer-vision aimbots invisible to client AC:** YOLO on screen/capture card + hardware input emulation (Surfshark research Feb 2026; PC Gamer 2025 mousepad-moving Valorant aimbot). No memory reads → Vanguard/EAC can't see them.
3. **"Humanized" cheats:** trained hesitation, missed shots, curved mouse paths (GAN-Aimbots, Kanervisto et al. — evades automatic detection AND human judges).
4. **AI on attacker side elsewhere:** automated recon/fuzzing, credential stuffing (Roblox 2FA bypass reports Dec 2024), economy botting, LLM phishing.

### What AI did NOT change
- Every cheat still sends packets through your protocol → server-side validation cannot be bypassed by AI (GAN-Aimbots paper: behavioral server analysis "cannot be bypassed").
- 2026 defense trend = **server-side AI anomaly detection**: YAACS (arXiv 2607.04336, Jul 2026: 88.6% acc / 0.97% FPR, Stacked LSTM on 128 ticks), FairFight/VACNet-style behavioral systems. Tech4Gamers (Mar 2026): "AI Anti-Cheat is Finally Winning."

### Defense mapping (lab plan)
- AI-written protocol exploits → NET-3 movement validation, NET-1/2 count caps, NET-4 rate limits (server-authoritative)
- AI farm bots → rate limits + packet-timing telemetry
- AI-injected memory hacks → accept client compromise; never trust client
- Web-game JS exposure → server-validated protocol + HMAC ticket auth (SERVER-SECURITY.md)
- AI fuzzing/DoS on tunnel → Portwarp + firewall, duplicatePeers=2, ConnectionsLimit, handshake rate limits
- Credential attacks → 2FA + revocable HMAC tickets

## 5. Reddit round (2026-08-01) — firsthand stories

### Economy-killer cases (r/gamedev "What's the Worst Economy Hacks")
- **New World (Amazon):** massive item-dupe outbreak — devs "playing whack-a-mole with the dupes, shutting down trading/AH between players. Caused massive trust issues in the player base and lots of people quit" (r/gamedev, 2023).
- **World of Warcraft:** banned tens of thousands for an item-duplication glitch and had to **roll server state back** (r/gamedev OP).
- **Generic AAA MMORPG dupe:** "spread like wildfire and the economy got totally wrecked... I stopped playing shortly after, together with most of the playerbase. They were too slow finding a way to reliably identify offenders and missed their rollback window." → **the dupe-then-rollback timing lesson.**

### The arms-race cases
- **Hypixel (Minecraft, 100k+ concurrent):** Watchdog behavioral anti-cheat vs hacked clients. Aug 2025 wave thread: cheaters brag openly ("Everyone is cheating, so I have to cheat"), players stopped reporting because "nothing will happen." Hypixel's own FAQ: *"Will Hypixel ever be cheater-free? No, it is impossible."* → **behavioral AC + constant updates is the only winning posture, and even it is a war of attrition.**
- **Red Dead Online:** r/RedDeadOnline "Hackers/modders have ruined my favorite game" — PC modders/hackers cited as a major reason Rockstar abandoned RDO content updates.
- **Rust:** r/gaming "CHEATERS RUINING RUST, RAIDED / DESTROYED BY HACKERS."
- **GTA V Online:** hackers teleport/kick/crash players' games (Steam discussions).
- **Battlefield V (EA forums):** "Cheaters sabotaging PC servers, draining player counts then switching servers."
- **Mini Militia (mobile):** "Hackers destroyed this game" (viral May 2026).

### Reddit lessons for the lab
1. **Dupe/exploit → economy death has a rollback window** — detect fast (server-side anomaly telemetry) or you can never roll back without revolt.
2. **Cheaters normalize cheating** ("everyone does it") — enforcement speed matters; slow bans (Hypixel 20–30 min waves) breed "nothing happens" resignation.
3. **Even perfect server validation doesn't stop CV/humanized bots** — behavior telemetry + server authority is the only layer that can't be bypassed.
4. **Hackers sabotage servers themselves** (BFV server-draining, GTA crashing) — rate limits + per-IP caps are live-server survival basics.

## Key sources
- gamedeveloper.com "Yager sunsetting The Cycle: Frontier after cheaters cause irreparable damage" (2023)
- getgud.io "The Graveyard of Games: Titles That Died Due to Cheaters and Griefers" (2024)
- thegamer.com "The Best MMOs That Have Been Shut Down" (2025)
- unknowncheats.me (RYL threads 2005–2025: multihit, duping, "original server shutdown long ago because of hacking"; krunker.io threads)
- xunleashed.com RYL hacks (damage edit, GameGuard bypass)
- ragezone.com RYL section (server files, netbug/GMhack/party bug)
- mmohuts.com / mmos.com RYL reviews (Youxiland, 2005 launch, ROW 2017 relaunch)
- reddit.com r/MMORPG "RYL2, a dead MMO?" (subscription-swap death)
- github.com Ap0dexMe0/RYL / ThatNotEasy/RYL (RYL security research); Ap0dexMe0/RiskYourLife-Macros
- haveibeenpwned.com/Breach/Roblox (2016); roblox.com HackerOne policy; devforum.roblox.com 2FA bypass report
- github.com neutro74/krunker.exploits; unknowncheats.me krunker.io tags; cheater.ninja browser games
- arxiv.org 2607.04336 (YAACS server-side aimbot detection, Jul 2026)
- surfshark.com research (Feb 2026): AI/CV cheat trend, hardware input emulation
- pcgamer.com (2023 Rocket League ML bot; 2025 mousepad-moving Valorant aimbot)
- tech4gamers.com "AI Anti-Cheat is Finally Winning in 2026" (Mar 2026)
- github.com/orgs/community discussion #198741 "Is AI quietly changing the cheating problem?" (Jun 2026)
- Kanervisto, Kinnunen, Hautamäki — "GAN-Aimbots: Using Machine Learning for Cheating in First Person Shooters" (IEEE ToG, 2022)
- reddit.com/r/gamedev "What's the Worst Economy Hacks and How Did You Fix Them?" (142skxb); r/NewWorld (Silver/Gold dupe saga); r/gaming Rust "RAIDED / DESTROYED BY HACKERS"; r/RedDeadOnline 187u4hk; r/hypixel pvq0zh (Aug 2025 Bedwars wave) + nuvukl (Watchdog anti-kb); hypixel.net support FAQ ("Will Hypixel ever be cheater-free?"); r/MMORPG ww3wkh (exploit stories); r/diablo3 "Gold Dupe Exploit Cripples D3 Economy"; r/MortalOnline 1cmq24b (exploits/RMT); ea.com forums (Battlefield V server sabotage); steamcommunity.com GTA V hacker reports; youtube "How Hackers DESTROYED Hypixel Forever" (Jun 2026); instagram Mini Militia "Hackers destroyed this game" (May 2026)
