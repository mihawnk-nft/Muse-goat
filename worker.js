// Muse Goat — Proof Gatekeeper endpoint (v2)
// Agent Games by zkVerify. Cloudflare Worker (plain JS, no build step).
//
// v2 (2026-11-15): REAL task envelope (from /events/proof-gatekeeper sample
// task payload, verified by research 15 Nov): decision fields live NESTED
// under `input` with different names (registered_vk, proof_vk, minimum,
// public_balance, expiry_block, current_block, recipient,
// condition_recipient, amount, max_transfer, proof_tx). v1 assumed FLAT
// top-level fields — it would have REJECTED every real task with
// MISSING_FIELD_VK. v2 unwraps `input` (top-level kept as fallback).
//
// v2 also fixes the preflight classification: a body is a TASK only if it
// carries an `input` object or decision fields. A `task_id` (or a
// proof-gatekeeper `type`) WITHOUT decision fields is a probe → signed
// handshake. (Hypothesis for the dashboard's stubborn "must return signed
// protocol-v1 JSON": its probe carries a task_id/type and v1.x
// misclassified it as a task → 401 / MISSING_FIELD_VK.)
//
// Proof: still v1 scope — proof:null / public_signals:null (-2 penalty);
// Groth16 proof generation + Kurier submit + poll-to-Finalized is the
// next upgrade. Response task shape echoes `proof_tx` (event page
// example) alongside proof/public_signals.
//
// Response signing is back to the STANDARD convention (secret string as
// HMAC key). v1.5's hex-decoded signing experiment failed preflight too,
// so the convention was not the cause. Request verification still accepts
// both conventions (v1.4).
//
// SECURITY: the HMAC secret is NEVER in this repo. It comes from the
// dashboard "Rotate Secret" as env.AGENT_GAMES_HMAC_SECRET. Never commit
// .env, never paste the secret in chat, never log it.

// Gatekeeper verification-key hash (zkVerify mainnet,
// GET https://agentgames.zkverify.io/api/circuit-info). Reserved for future
// Groth16 proof verification (snarkjs/Kurier); NOT a decide() check — the
// task's registered_vk is the anchor (see decide check 1).
const GATEKEEPER_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

// --- Field map -----------------------------------------------------------
// Real envelope field names first (events/proof-gatekeeper sample), legacy
// flat names as fallback. First present value wins. A missing required
// field fails CLOSED (REJECT), it never guesses a value.
const F = {
  registeredVk: ["registered_vk", "registeredVk", "registeredVK", "vkHash", "vk_hash", "verificationKeyHash"],
  proofVk: ["proof_vk", "proofVk", "proofVK"],
  proofTx: ["proof_tx", "proofTx", "proofReference", "proof_reference", "proofRef", "reference"],
  recipient: ["recipient", "to", "payee"],
  conditionRecipient: ["condition_recipient", "conditionRecipient"],
  amount: ["amount", "value"],
  maxTransfer: ["max_transfer", "maxTransfer", "maxAmount"],
  minimum: ["minimum", "minBalance", "minimumBalance", "threshold"],
  publicBalance: ["public_balance", "publicBalance", "balance"],
  expiryBlock: ["expiry_block", "expiryBlock", "deadlineBlock", "expiry", "deadline"],
  currentBlock: ["current_block", "currentBlock"],
  issuedAt: ["issued_at", "issuedAt", "timestamp", "ts"],
  deadlineAt: ["deadline_at", "deadlineAt"],
  taskId: ["taskId", "task_id", "id"],
  type: ["type"],
  circuit: ["circuit", "circuitId", "circuit_id"],
  proofSystem: ["proofSystem", "proof_system"],
};

function pick(env, names) {
  for (const n of names) if (env[n] !== undefined && env[n] !== null) return env[n];
  return undefined;
}

// --- Crypto helpers (WebCrypto, Workers runtime) -------------------------
const enc = new TextEncoder();

async function hmacHex(secret, data, hexKey = false) {
  let keyData = enc.encode(secret);
  if (hexKey) {
    const clean = secret.trim().toLowerCase();
    if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) return null;
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    keyData = bytes;
  }
  const key = await crypto.subtle.importKey(
    "raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Constant-time string compare (avoid early-exit timing leak).
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function signBody(secret, body) {
  // Standard convention: the secret string as the HMAC key.
  return hmacHex(secret, body, false);
}

function jsonResponse(secret, obj, status = 200) {
  const body = JSON.stringify(obj);
  return signBody(secret, body).then((sig) =>
    new Response(body, {
      status,
      headers: {
        "content-type": "application/json",
        "x-agent-games-signature": sig,
      },
    })
  );
}

// --- Temporary diagnostic log buffer --------------------------------------
// In-memory ring buffer (per isolate) of recent request metadata. Read via
// GET /debug-logs?k=musegoat-debug. REMOVE once preflight is fixed.
const LOG_BUF = [];
function logEvt(o) {
  try {
    LOG_BUF.push({ t: Date.now(), ...o });
    if (LOG_BUF.length > 20) LOG_BUF.shift();
  } catch {}
  try { console.log(JSON.stringify(o)); } catch {}
}

// --- Proof-reuse seen-set -------------------------------------------------
// In-memory only. A Worker isolate restart clears it, so for production
// move this to Workers KV (binding SEEN) — a reused proofTx must stay
// rejected across restarts. NEVER approve a proofTx seen before.
const seenProofRefs = new Set();

// --- Time parsing ----------------------------------------------------------
// Accepts epoch seconds/ms (number or numeric string) and ISO strings.
// Returns ms-since-epoch, or undefined when unparseable (caller skips the
// check instead of failing on a placeholder value).
function parseTime(v) {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "number" && Number.isFinite(v)) return v < 1e12 ? v * 1000 : v;
  if (typeof v === "string") {
    const s = v.trim();
    if (/^\d+$/.test(s)) {
      const n = Number(s);
      return n < 1e12 ? n * 1000 : n;
    }
    const d = Date.parse(s);
    if (Number.isFinite(d)) return d;
  }
  return undefined;
}

// --- Decision logic: deterministic checks on the REAL envelope -----------
// Returns { decision: "APPROVE"|"REJECT", reason_code, proof_tx? }.
// Fail closed: any missing/invalid input, any failed check, any exception
// inside here => REJECT. An LLM never makes the final call.
function decide(env) {
  // Merge: `input` wins for decision fields; top-level kept for
  // task_id/type and as a legacy flat fallback.
  const inp = env.input && typeof env.input === "object" && !Array.isArray(env.input) ? env.input : {};
  const d = { ...env, ...inp };
  const proofTxRaw = pick(d, F.proofTx);
  const proofTx = proofTxRaw !== undefined ? String(proofTxRaw) : undefined;
  const fail = (reason_code) => ({
    decision: "REJECT",
    reason_code,
    ...(proofTx !== undefined ? { proof_tx: proofTx } : {}),
  });

  // 0. Task type must be the Proof Gatekeeper game (when present).
  const type = pick(d, F.type);
  if (type !== undefined) {
    const t = String(type).toLowerCase();
    if (!t.includes("proof-gatekeeper") && !t.includes("gatekeeper")) return fail("BAD_CIRCUIT");
  }

  // 1. Verification key: the proof's VK must match the registered VK.
  // (The event page's trap example: proof_vk != registered_vk => REJECT
  // with VK_SUBSTITUTION.)
  const regVk = pick(d, F.registeredVk);
  const proofVk = pick(d, F.proofVk);
  if (regVk === undefined || proofVk === undefined) return fail("MISSING_FIELD_VK");
  if (String(proofVk).toLowerCase() !== String(regVk).toLowerCase()) {
    return fail("VK_SUBSTITUTION");
  }

  // 2. Recipient: valid address and matching the condition recipient.
  const recipient = pick(d, F.recipient);
  if (recipient === undefined) return fail("MISSING_FIELD_RECIPIENT");
  if (!/^0x[0-9a-fA-F]{40}$/.test(String(recipient))) return fail("BAD_RECIPIENT");
  const condRecipient = pick(d, F.conditionRecipient);
  if (condRecipient !== undefined &&
      String(condRecipient).toLowerCase() !== String(recipient).toLowerCase()) {
    return fail("RECIPIENT_MISMATCH");
  }

  // 3. Threshold: public balance must meet the minimum.
  const minimum = pick(d, F.minimum);
  const pubBal = pick(d, F.publicBalance);
  if (minimum === undefined || pubBal === undefined) return fail("MISSING_FIELD_THRESHOLD");
  const minN = Number(minimum);
  const balN = Number(pubBal);
  if (!Number.isFinite(minN) || !Number.isFinite(balN)) return fail("BAD_THRESHOLD");
  if (balN < minN) return fail("THRESHOLD_MISMATCH");

  // 4. Amount: positive and within the max transfer.
  const amount = pick(d, F.amount);
  if (amount === undefined) return fail("MISSING_FIELD_AMOUNT");
  const amt = Number(amount);
  if (!Number.isFinite(amt) || amt <= 0) return fail("BAD_AMOUNT");
  const maxT = pick(d, F.maxTransfer);
  if (maxT !== undefined) {
    const maxN = Number(maxT);
    if (!Number.isFinite(maxN)) return fail("BAD_MAX_TRANSFER");
    if (amt > maxN) return fail("AMOUNT_EXCEEDS_MAX");
  }

  // 5. Expiry: current block must not pass the expiry block.
  const expiry = pick(d, F.expiryBlock);
  const current = pick(d, F.currentBlock);
  if (expiry !== undefined && current !== undefined) {
    const e = Number(expiry);
    const c = Number(current);
    if (Number.isFinite(e) && Number.isFinite(c) && c > e) return fail("EXPIRED");
  }

  // 6. Timestamps: issued_at reasonably fresh (60 min tolerance for
  // delivery delay), deadline_at in the future.
  const issued = parseTime(pick(d, F.issuedAt));
  if (issued !== undefined && Math.abs(Date.now() - issued) > 60 * 60 * 1000) {
    return fail("BAD_TIMESTAMP");
  }
  const deadline = parseTime(pick(d, F.deadlineAt));
  if (deadline !== undefined && deadline < Date.now()) return fail("EXPIRED");

  // 7. Proof reference not reused.
  if (proofTx === undefined) return fail("MISSING_FIELD_PROOF");
  if (seenProofRefs.has(proofTx)) return fail("PROOF_REUSED");

  // All checks passed. Mark the proofTx as seen (only on APPROVE).
  // (Proof verification against the gatekeeper VK + Finalized polling is
  // the next upgrade; v2 returns proof:null and takes the -2 penalty.)
  seenProofRefs.add(proofTx);
  return {
    decision: "APPROVE",
    reason_code: "OK",
    proof_tx: proofTx,
  };
}

// --- HTTP handler ---------------------------------------------------------
export default {
  async fetch(request, env) {
    const secret = env.AGENT_GAMES_HMAC_SECRET;
    if (!secret) {
      return new Response("misconfigured: AGENT_GAMES_HMAC_SECRET not set", { status: 500 });
    }

    const url = new URL(request.url);
    const sigHeader = request.headers.get("x-agent-games-signature") || "";

    // GET/HEAD = health/preflight probe (no body to sign): answer handshake.
    if (request.method === "GET" || request.method === "HEAD") {
      // Temporary diagnostic: recent request log (see LOG_BUF above).
      if (url.pathname === "/debug-logs" && request.method === "GET") {
        if (url.searchParams.get("k") !== "musegoat-debug") {
          return new Response("not found", { status: 404 });
        }
        return new Response(JSON.stringify(LOG_BUF), {
          headers: { "content-type": "application/json" },
        });
      }
      logEvt({ m: request.method, p: url.pathname, sig: !!sigHeader });
      return jsonResponse(secret, { ok: true, protocolVersion: "v1" });
    }
    if (request.method !== "POST") {
      return new Response("method not allowed", { status: 405 });
    }

    let raw;
    try {
      raw = await request.text();
    } catch {
      return jsonResponse(secret, { decision: "REJECT", reason_code: "BAD_BODY" }, 400);
    }

    let envObj = null;
    let jsonOk = true;
    try {
      envObj = raw ? JSON.parse(raw) : null;
    } catch {
      jsonOk = false;
    }

    // HMAC over the RAW body, compared to the header. Both key conventions
    // are accepted (secret as string, secret hex-decoded); the log records
    // which one matched.
    /** @type {"str" | "hex" | false} */
    let sigKind = false; // "str" | "hex" | false
    try {
      const expStr = await hmacHex(secret, raw, false);
      if (expStr && safeEqual(sigHeader.trim().toLowerCase(), expStr)) sigKind = "str";
      else {
        const expHex = await hmacHex(secret, raw, true);
        if (expHex && safeEqual(sigHeader.trim().toLowerCase(), expHex)) sigKind = "hex";
      }
    } catch {
      sigKind = false;
    }
    const sigOk = sigKind !== false;

    // Debug log: method, path, which signature convention matched, body
    // length, top-level KEYS only — never values, never the secret. Lets
    // the owner read in Cloudflare Logs exactly what the platform sends.
    let keys = null;
    if (envObj && typeof envObj === "object" && !Array.isArray(envObj)) {
      keys = Object.keys(envObj);
    }
    logEvt({ m: request.method, p: url.pathname, sig: sigKind, len: raw.length, json: jsonOk, keys });

    // Unparseable body can never be a platform preflight (it sends valid
    // JSON) — fail closed, signed.
    if (!jsonOk) {
      return jsonResponse(secret, { decision: "REJECT", reason_code: "BAD_JSON" }, 400);
    }

    // Preflight handshake shapes (signed or not) get the SIGNED
    // {ok:true, protocolVersion:"v1"} reply.
    const isPreflightShape =
      envObj && typeof envObj === "object" &&
      (envObj.type === "preflight" || envObj.preflight === true ||
        envObj.type === "health" || envObj.type === "healthcheck" ||
        envObj.type === "ping" || envObj.type === "handshake");
    if (isPreflightShape) {
      const resp = { ok: true, protocolVersion: "v1" };
      if (typeof envObj.challenge === "string") resp.challenge = envObj.challenge;
      if (typeof envObj.nonce === "string") resp.nonce = envObj.nonce;
      return jsonResponse(secret, resp);
    }

    // A parseable body that is not a JSON object (empty, null, string,
    // number, array) can never be a decision task — answer the handshake.
    if (!envObj || typeof envObj !== "object" || Array.isArray(envObj)) {
      return jsonResponse(secret, { ok: true, protocolVersion: "v1" });
    }

    // TASK or PROBE? A body is a task ONLY if it carries an `input` object
    // or decision fields. A `task_id` / proof-gatekeeper `type` WITHOUT
    // decision fields is a probe → signed handshake (v1.x misclassified
    // such probes as tasks → 401 / MISSING_FIELD_VK).
    const hasInput =
      envObj.input && typeof envObj.input === "object" && !Array.isArray(envObj.input);
    const hasDecisionField =
      pick(envObj, F.registeredVk) !== undefined ||
      pick(envObj, F.proofVk) !== undefined ||
      pick(envObj, F.proofTx) !== undefined ||
      pick(envObj, F.recipient) !== undefined ||
      pick(envObj, F.amount) !== undefined ||
      pick(envObj, F.minimum) !== undefined ||
      pick(envObj, F.publicBalance) !== undefined ||
      (hasInput && (
        pick(envObj.input, F.registeredVk) !== undefined ||
        pick(envObj.input, F.proofVk) !== undefined ||
        pick(envObj.input, F.proofTx) !== undefined ||
        pick(envObj.input, F.recipient) !== undefined ||
        pick(envObj.input, F.amount) !== undefined ||
        pick(envObj.input, F.minimum) !== undefined ||
        pick(envObj.input, F.publicBalance) !== undefined));
    if (!hasInput && !hasDecisionField) {
      return jsonResponse(secret, { ok: true, protocolVersion: "v1" });
    }

    // Decision task. Signature REQUIRED; any exception fails closed.
    if (!sigOk) {
      return jsonResponse(secret, { decision: "REJECT", reason_code: "BAD_SIGNATURE" }, 401);
    }

    let result;
    try {
      result = decide(envObj);
    } catch {
      result = { decision: "REJECT", reason_code: "ERROR" };
    }

    // v2: no Groth16 proof yet (proof:null). The response echoes proof_tx
    // (event page example) alongside proof/public_signals.
    const resp = {
      decision: result.decision,
      reason_code: result.reason_code,
      proof: null,
      public_signals: null,
    };
    if (result.proof_tx !== undefined) resp.proof_tx = result.proof_tx;
    return jsonResponse(secret, resp);
  },
};
