# AI-SENTINEL — Mini-AI Server Watchdog for the Flax Game (spec)

**Purpose:** 24/7 cheat/attack detection on the Flax game server using a small
on-device model, built **exactly on the pattern already proven in the FlaxMCP
repo** (in-process ONNX classifiers: query-router, tool-intent, reranker —
`docs/research/train-mini-ai-on-flax-code.md` §9.5–9.8, `scripts/training/`,
`external/models/`).

**Reference pattern (copy this shape):**
- Python: `scripts/training/build-*-dataset.py` → `train-*.py` → ONNX export
  (self-contained, `export_params=True` — the external_data pitfall is
  documented in §9.8) → optional `quantize-onnx-model.py` + fixture
  validation → provenance receipt.
- C#: lazy-singleton provider, env-var model path, graceful fallback,
  **advisory-only** — "no model performs direct dispatch; every model
  degrades gracefully" (the repo's own architectural rules, which are
  exactly right for a cheat sentinel).
- Compute: free (RTX 3050, ~85 s training runs; CPU inference ~10 ms).

**Location note:** this repo (antivirus lab) is the spec + the attack-data
generator. Implementation goes in the game repo (`samples/game-project`),
guided by `docs/SECURITY-BY-DESIGN.md` (telemetry + hooks) and this doc.

---

## 1. Architecture (3 tiers)

```
per-packet (always on, zero ML):      T0 thresholds  (integer math, in SessionMetrics)
per-session (on flag / every 60 s):   T1 Isolation Forest  → ONNX, ~1 ms CPU
after labels accumulate:              T2 supervised MLP    → ONNX, same path
                        ↓
              flag → shadow queue → human review → confirmed label
                                              ↓ (exports labels for retraining)
```

| Tier | Model | Labels needed | When |
|---|---|---|---|
| T0 | Rules + rolling z-scores (SECURITY-BY-DESIGN Rule 4) | none | ship first, always on |
| T1 | Isolation Forest (sklearn → ONNX via skl2onnx) | none (unsupervised) | after first lab attack sessions |
| T2 | MLP classifier, 2-3 classes (torch → ONNX, same shape as `train-query-router.py`) | lab attacks + confirmed reviews | once ≥ ~500 labeled sessions |

**Advisory-only (hard rule, copied from FlaxMCP):** the sentinel never
disconnects, bans, or rate-limits by itself. It flags. A human (you) reviews
the shadow queue. Confirmed labels feed the next training round. Wrong bans
kill trust (Hypixel high-ping false-ban lesson) — never auto-ban on ML.

---

## 2. Feature vector (session-level, ~14 numeric features)

Extracted by `SessionMetrics` (SECURITY-BY-DESIGN Rule 4), serialized to one
JSON line per session.

| # | Feature | Attack it catches | Source |
|---|---|---|---|
| 1 | sessionDuration (s) | bot churn | server |
| 2 | packetsPerSecond (mean / p95 / max) | floods | rolling window |
| 3 | bytesPerSecond (mean / max) | floods, giant packets | rolling window |
| 4 | packetSizeVariance | fuzzing (packet-soup) | all packets |
| 5 | transformPps (mean) | transform spam | per-packet counter |
| 6 | maxMovementDelta (units/tick) | teleport / speed hack | NET-3 clamp value |
| 7 | speedExceededCount | speed hack (clamped = still caught) | NET-3 drops |
| 8 | badMacCount | forged tools / WPE / proxy | auth envelope drops |
| 9 | replaySeqCount | replay attacks | auth envelope drops |
| 10 | unknownPacketIdCount | fuzzers / protocol probing | PacketRegistry drops |
| 11 | handshakeAttemptsFromIp | connect flood (NET-4) | per-IP counter |
| 12 | hitAccuracy (hits / shots) | fake-hit cheats | combat path |
| 13 | burstiness (max packets in 1 s / mean) | burst attacks, lag-switch | window |
| 14 | pingJitter (σ of RTT) | lag switch | ENet ping stats |

v2 (when combat/aim exists): reaction-time consistency (AI aimbots),
input-interval stddev (macros), engagement-coincidence bursts (Anybrain tell).

**Normalization:** z-score or min-max per feature; record the fit parameters
with the model (receipt file) so C# preprocesses identically.

---

## 3. Dataset builder (the lab is the generator)

`scripts/sentinel/build-sentinel-dataset.py` (new, in THIS repo — shape:
`build-query-router-dataset.py`):

- **Attack class:** run each lab tool against the game server and capture
  SessionMetrics: `flax_enet.py` flood modes, `fuzz_enet.py` mutations,
  forged PlayersTransform (teleport/speed), no-MAC and replay-seq packets,
  connect-loop handshake spam, unknown-ID soup.
- **Clean class (pre-launch):** synthetic "normal" sessions via
  `flax_enet.py` walkthrough mode (move at max speed, 30-60 Hz transforms,
  sane chat) — and, once live, real player sessions.
- **Confirmed class:** exported shadow-queue reviews (`sentinel/labels/*.jsonl`).
- Output: `data/sentinel/train.jsonl` + `eval.jsonl` (80/20), with the raw
  feature vectors, not text.

---

## 4. Training + export (copy the proven scripts)

1. **T1:** `train-sentinel-isolation-forest.py` — sklearn `IsolationForest`
   on train.jsonl; calibrate contamination on eval so FPR < 1% (YAACS
   benchmark: 88.6% acc / 0.97% FPR is the bar to beat); export via
   `skl2onnx` (self-contained — same `external_data` lesson as §9.8).
2. **T2 (later):** `train-sentinel-classifier.py` — small MLP (2-3 hidden
   layers, ~50K params), torch → ONNX, same structure as
   `train-query-router.py` (per-class metrics, export_params=True).
3. **Quantization:** reuse `quantize-onnx-model.py` pattern **with fixture
   validation** — dynamic int8 broke top-1 agreement in their repo; stay
   float32 unless the fixture suite passes.
4. **Receipt + manifest:** `receipts/sentinel-v1.receipt.json` (features,
   fit params, FPR/TPR on eval, model SHA-256) — same discipline as
   `external/models/receipts/`.
5. **Training cost:** seconds on your RTX 3050. **$0.**

---

## 5. C# integration (game repo — modeled on `QueryRouterProvider.cs`)

- `SentinelModelProvider` — lazy singleton; env var `GAME_SENTINEL_MODEL_PATH`
  pointing at the model dir (must be set before server start, like their
  `FLAXMCP_QUERY_ROUTER_MODEL_PATH`).
- Per session: T0 streaming (always on, no model needed); every 60 s *or at
  disconnect*, build the feature vector → ONNX inference (~1 ms for a small
  MLP/IF) → if anomaly score above threshold → write
  `sentinel/flags/<session>.jsonl` entry (feature vector + score + reasons).
- **Graceful degradation:** no model file / load error → T0 only; never
  crashes the game loop (their rule: "every model degrades gracefully").
- **Advisory only:** flags → shadow queue (kept playing, marked); review UI
  or nightly report; confirmed → `sentinel/labels/confirmed.jsonl` → next
  training round. Model version is part of the flag record.

---

## 6. Ops loop (the 24/7 part)

```
server (always on) → session telemetry jsonl + flags
        ↓ nightly (script)
python train-sentinel*.py (retrain on all data incl. confirmed labels)
        ↓
receipt + model.onnx vN → GAME_SENTINEL_MODEL_PATH → restart server
        ↓
you review shadow queue → confirmed labels → next round
```

- Data lives in `sentinel/raw/` (rotated daily), labels in `sentinel/labels/`.
- **Threshold discipline:** keep the model + thresholds secret from players
  (a leaked detector = a detector you can dodge — same reason we never
  publish protocol docs).
- **Adversarial ML reality:** a determined cheater can probe the detector by
  playing borderline sessions. Mitigation: retrain on each new attack shape
  from the lab (the lab keeps producing new ones), bump model version,
  vary thresholds slightly per version. The sentinel is a *cost raiser* and
  *catcher*, not a wall — the wall is server authority (SECURITY-BY-DESIGN).

---

## 7. Test matrix (lab acceptance)

| Attack | Feature that must flag | Verify with |
|---|---|---|
| Packet flood | pps/bytes p95, burstiness | `flax_enet.py` flood mode + attack-run.ps1 |
| Connect-loop handshake spam | handshakeAttemptsFromIp | connect-loop mode |
| Forged transform (teleport) | maxMovementDelta, speedExceededCount | forged payloads |
| No-MAC / bad seq | badMacCount, replaySeqCount | auth-envelope tests |
| Unknown packet soup | unknownPacketIdCount, sizeVariance | fuzz_enet.py |
| Clean baseline (10 sessions) | **0 flags** (FPR check) | walkthrough mode |

Each attack in `attack-run.ps1` gains a "sentinel flags fired?" assertion.
FPR gate: < 1% on clean sessions before any live deployment.

---

## 8. Phases

1. **P0 (no live server yet):** build `SessionMetrics` T0 into the game with
   the NET-1/2/4 fixes (SECURITY-BY-DESIGN priority order).
2. **P1 (lab server live):** dataset builder + T1 training + ONNX + C#
   provider; run the test matrix; iterate until clean sessions are quiet and
   every attack flags.
3. **P2 (public):** calibrate thresholds on real traffic (FPR < 1%), shadow
   queue live, nightly retrain.
4. **P3:** T2 supervised model from confirmed labels; v2 features (aimbot
   tells) when combat stats exist.

*Reference: SECURITY-BY-DESIGN.md (telemetry + hooks), WIRE-FORMAT.md,
FINDINGS-001 (NET-1..5), ARSENAL F4 (tells) / F6-F7 (spec + acceptance),
FlaxMCP pipeline docs (train-mini-ai-on-flax-code.md §9.5-9.8, onnx-routing-runbook.md).*
