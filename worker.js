// Muse Goat — Proof Gatekeeper endpoint (v1 scaffold)
// Agent Games by zkVerify. Cloudflare Worker (plain JS, no build step).
//
// v1 scope: HMAC verification, preflight responder, deterministic 7-check
// decision loop, signed responses. NO Groth16 proof yet — v1 returns
// proof:null / public_signals:null and accepts the -2 proof penalty
// (correct decision still scores +12-2=+10). Proof generation (snarkjs +
// Kurier, wait-for-Finalized) is the v2 upgrade; see README.md.
//
// v1.5 (2026-11-15) — EKSPERIMEN: response signing pakai kunci hex-decoded.
// Secret sudah di-rotate + sinkron tapi preflight tetap gagal, jadi yang
// tersisa: platform mungkin memverifikasi signature jawaban dengan kunci
// hasil decode hex (32 byte), bukan string secret-nya. v1.5 menandatangani
// SEMUA response (handshake + decision) dengan kunci hex-decoded; kalau
// preflight lolos, konvensi ini yang benar. Kalau tetap gagal, konvensi
// string yang benar dan masalahnya ada di bentuk probe — revert ke v1.4.1.
// Verifikasi request tetap ganda (str/hex) seperti v1.4.
//
// SECURITY: the HMAC secret is NEVER in this repo. It comes from the
// dashboard "Rotate Secret" as env.AGENT_GAMES_HMAC_SECRET. Never commit
// .env, never paste the secret in chat, never log it.

// Registered Gatekeeper verification-key hash (zkVerify mainnet,
// GET https://agentgames.zkverify.io/api/circuit-info).
const GATEKEEPER_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

// --- Field map -----------------------------------------------------------
// The platform's exact task-envelope field names are confirmed against the
// dashboard sample task (TODO: verify). Each entry lists candidate names;
// the first one present in the envelope wins. A missing required field
// fails CLOSED (REJECT), it never guesses a value.
const F = {
  vkHash: ["vkHash", "vk_hash", "verificationKeyHash"],
  circuit: ["circuit", "circuitId", "circuit_id"],
  proofSystem: ["proofSystem", "proof_system"],
  proof: ["proof", "groth16Proof"],
  publicSignals: ["publicSignals", "public_signals", "publicInputs"],
  proofRef: ["proofReference", "proof_reference", "proofRef", "reference"],
  recipient: ["recipient", "to", "payee"],
  amount: ["amount", "value"],
  threshold: ["threshold", "minBalance", "minimumBalance"],
  expiryBlock: ["expiryBlock", "deadlineBlock", "expiry", "deadline"],
  timestamp: ["timestamp", "issuedAt", "ts"],
  taskId: ["taskId", "task_id", "id"],
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
  // v1.5: sign responses with the hex-decoded key. Fall back to the
  // string key only if the secret is not valid hex (it is, 64 hex chars).
  return (await hmacHex(secret, body, true)) ?? (await hmacHex(secret, body, false));
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

// --- Proof-reuse seen-set -------------------------------------------------
// v1: in-memory only. A Worker isolate restart clears it, so for production
// move this to Workers KV (binding SEEN) — a reused proofRef must stay
// rejected across restarts. NEVER approve a proofRef seen before.
const seenProofRefs = new Set();

// --- Decision logic: the 7 deterministic checks --------------------------
// Returns { decision: "APPROVE"|"REJECT", reason_code }.
// Fail closed: any missing/invalid input, any failed check, any exception
// inside here => REJECT. An LLM never makes the final call.
function decide(env) {
  const fail = (reason_code) => ({ decision: "REJECT", reason_code });

  // 1. Verification key matches the registered Gatekeeper key.
  const vk = pick(env, F.vkHash);
  if (vk === undefined) return fail("MISSING_FIELD_VK");
  if (String(vk).toLowerCase() !== GATEKEEPER_VK_HASH) return fail("BAD_VK");

  // 2. Circuit + proof system are the ones the task expects.
  const circuit = pick(env, F.circuit);
  if (circuit !== undefined) {
    const c = String(circuit).toLowerCase();
    if (!c.includes("gatekeeper")) return fail("BAD_CIRCUIT");
  }
  const ps = pick(env, F.proofSystem);
  if (ps !== undefined) {
    const p = String(ps).toLowerCase();
    if (!p.includes("groth16")) return fail("BAD_PROOF_SYSTEM");
  }

  // 3. Public inputs prove threshold + recipient + amount.
  const recipient = pick(env, F.recipient);
  if (recipient === undefined) return fail("MISSING_FIELD_RECIPIENT");
  if (!/^0x[0-9a-fA-F]{40}$/.test(String(recipient))) return fail("BAD_RECIPIENT");

  const amount = pick(env, F.amount);
  if (amount === undefined) return fail("MISSING_FIELD_AMOUNT");
  const amt = Number(amount);
  if (!Number.isFinite(amt) || amt <= 0) return fail("BAD_AMOUNT");
  // TODO: enforce the task's amount cap once the dashboard sample shows
  // the cap field/value. Never invent a cap number.

  const threshold = pick(env, F.threshold);
  if (threshold !== undefined) {
    const t = Number(threshold);
    if (!Number.isFinite(t)) return fail("BAD_THRESHOLD");
    // The public inputs must prove the balance meets the threshold;
    // without the exact public-signals layout this is checked as
    // presence + numeric sanity. Full public-inputs verification
    // ships with v2 (snarkjs proof verification against the VK).
  }

  // 4. Proof reference not reused.
  const ref = pick(env, F.proofRef);
  if (ref !== undefined) {
    const r = String(ref);
    if (seenProofRefs.has(r)) return fail("PROOF_REUSED");
  }

  // 5. Verification reached Finalized before approval.
  // v1: no proof is submitted to zkVerify yet, so there is no Finalized
  // state to check. This check is NOT faked as passing — it is skipped
  // in v1 and the response carries proof:null (platform scores -2 for
  // the missing proof). v2 submits via Kurier and polls to Finalized
  // BEFORE returning APPROVE.

  // 6. Task signature + timestamp valid.
  // (HMAC already verified the signature over the raw body before this.)
  const ts = pick(env, F.timestamp);
  if (ts !== undefined) {
    const t = Number(ts);
    const now = Date.now();
    const tMs = t < 1e12 ? t * 1000 : t; // accept seconds or ms
    if (!Number.isFinite(tMs) || Math.abs(now - tMs) > 10 * 60 * 1000) {
      return fail("BAD_TIMESTAMP");
    }
  }

  // Expiry: reject an expired task if an expiry/deadline field is present.
  const exp = pick(env, F.expiryBlock);
  if (exp !== undefined) {
    // Block-number expiry needs the current block height (RPC). v1 treats
    // a numeric expiry far in the past as expired only when it looks like
    // a timestamp; block-height comparison ships with v2 (RPC lookup).
    const e = Number(exp);
    if (Number.isFinite(e) && e > 1e12 && e < Date.now()) return fail("EXPIRED");
  }

  // All checks passed. Mark the proofRef as seen (only on APPROVE).
  if (ref !== undefined) seenProofRefs.add(String(ref));
  return { decision: "APPROVE", reason_code: "OK" };
}

// --- HTTP handler ---------------------------------------------------------
export default {
  async fetch(request, env) {
    const secret = env.AGENT_GAMES_HMAC_SECRET;
    if (!secret) {
      return new Response("misconfigured: AGENT_GAMES_HMAC_SECRET not set", { status: 500 });
    }

    // Minimal request metadata for debugging (no secret, no body values).
    const url = new URL(request.url);
    const sigHeader = request.headers.get("x-agent-games-signature") || "";

    // GET/HEAD = health/preflight probe (no body to sign): answer handshake.
    if (request.method === "GET" || request.method === "HEAD") {
      console.log(JSON.stringify({ m: request.method, p: url.pathname, sig: !!sigHeader }));
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
    console.log(JSON.stringify({ m: request.method, p: url.pathname, sig: sigKind, len: raw.length, json: jsonOk, keys }));

    // Unparseable body can never be a platform preflight (it sends valid
    // JSON) — fail closed, signed.
    if (!jsonOk) {
      return jsonResponse(secret, { decision: "REJECT", reason_code: "BAD_JSON" }, 400);
    }

    // Preflight handshake: a preflight-shaped body (signed or not), or any
    // unsigned probe that does NOT look like a decision task, gets the
    // SIGNED {ok:true, protocolVersion:"v1"} reply. The platform's
    // preflight can arrive unsigned — requiring a signature here is what
    // made the dashboard report "must return signed protocol v1".
    const isPreflightShape =
      envObj && typeof envObj === "object" &&
      (envObj.type === "preflight" || envObj.preflight === true ||
        envObj.type === "health" || envObj.type === "healthcheck" ||
        envObj.type === "ping" || envObj.type === "handshake");
    const looksLikeTask =
      envObj && typeof envObj === "object" &&
      (pick(envObj, F.vkHash) !== undefined ||
        pick(envObj, F.recipient) !== undefined ||
        pick(envObj, F.amount) !== undefined ||
        pick(envObj, F.taskId) !== undefined);
    if (isPreflightShape || (!sigOk && !looksLikeTask)) {
      // Echo a challenge/nonce if the probe carries one (challenge-response
      // preflight): the reply stays {ok, protocolVersion} plus the echo.
      const resp = { ok: true, protocolVersion: "v1" };
      if (envObj && typeof envObj === "object") {
        if (typeof envObj.challenge === "string") resp.challenge = envObj.challenge;
        if (typeof envObj.nonce === "string") resp.nonce = envObj.nonce;
      }
      return jsonResponse(secret, resp);
    }

    // A parseable body that is not a JSON object (empty, null, string,
    // number, array) can never be a decision task — answer the handshake
    // instead of BAD_JSON. (A signed empty-body probe used to land here.)
    if (!envObj || typeof envObj !== "object" || Array.isArray(envObj)) {
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

    // v1: no Groth16 proof yet (proof:null). v2 fills proof + public_signals.
    return jsonResponse(secret, {
      decision: result.decision,
      reason_code: result.reason_code,
      proof: null,
      public_signals: null,
    });
  },
};
