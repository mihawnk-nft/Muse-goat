# Muse Goat — Proof Gatekeeper agent (Agent Games by zkVerify)

Public HTTPS endpoint for the Proof Gatekeeper track. The platform POSTs
signed tasks; this worker verifies the HMAC, runs the 7 deterministic
checks, and returns a signed decision. No LLM makes the final call.

## Status: v1 scaffold (deployed? NO — see Deploy)

- [x] HMAC-SHA256 verification over the raw body (`x-agent-games-signature`)
- [x] Preflight responder: `{ ok: true, protocolVersion: "v1" }`, signed
- [x] Deterministic decision loop (VK match, circuit/proof system, public
      inputs threshold + recipient + amount, proof-reuse seen-set, timestamp)
- [x] Signed responses `{ decision, reason_code, proof, public_signals }`
- [x] Fail closed: any doubt, timeout, or error => REJECT
- [ ] Groth16 proof generation (snarkjs + gatekeeper.wasm/zkey) — v2
- [ ] Kurier submission + poll to Finalized before APPROVE — v2
- [ ] Workers KV seen-set (v1 seen-set is in-memory only) — v2

v1 returns `proof: null`, so each correct decision scores +12 -2 = +10
(no reliability bonus). v2 adds the proof for the full +12 + bonus.

## Spec sources (do not invent protocol details)

- https://agentgames.zkverify.io/build — task/response schemas, preflight,
  circuit artifacts, Security checklist (source of truth)
- https://agentgames.zkverify.io/guide — registration flow
- Circuit info: https://agentgames.zkverify.io/api/circuit-info
  - Gatekeeper vkHash:
    `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
  - Artifacts: `circuits/gatekeeper.wasm`,
    `circuits/gatekeeper_final.zkey`

## Assumptions to verify against the dashboard sample task (TODO)

- HMAC signature header is lowercase hex of HMAC-SHA256 over the raw body.
- Preflight arrives as a POST whose JSON has `type: "preflight"`
  (or `preflight: true`).
- Decision values are `"APPROVE"` / `"REJECT"`.
- `reason_code` strings are free-form (OK, BAD_VK, BAD_SIGNATURE, ...).
- Task-envelope field names: see the `F` field map at the top of
  `worker.js`. Confirm each against the real sample task and tighten it.

## Deploy (Cloudflare Workers)

Option A — dashboard (no CLI): create a Worker, paste `worker.js`,
set the secret below as an environment variable, deploy. The public URL
must be the FULL handler path you register, e.g.
`https://muse-goat.<subdomain>.workers.dev/agent` — note: this v1 worker
answers every POST path the same way; if you register a sub-path, point
the route at this worker.

Option B — wrangler:

```
npm i -g wrangler
wrangler login
wrangler secret put AGENT_GAMES_HMAC_SECRET   # paste the one-time secret
wrangler deploy
```

Then in the Agent Games dashboard (Your Agents → Muse Goat): set the
endpoint URL, run preflight (must pass before the platform marks the
agent active), then run an unscored practice task.

## Secrets

- `AGENT_GAMES_HMAC_SECRET`: one-time plaintext from the dashboard
  "Rotate Secret". Env var only. Never in this repo, never in chat logs.
  If lost, rotate again.
- `KURIER_API_KEY`: v2 only.

## Scoring (per task)

+12 correct decision · -6 approving a trap · -3 rejecting a valid request ·
-2 timeout/offline · -2 proof fails to verify · + reliability bonus
(verified proofs / tasks). 8 rounds/day, highest total wins.
