"use strict";
/**
 * MAME97-GK — Proof Gatekeeper agent endpoint.
 *
 * POST /agent accepts signed task envelopes
 * ("agent-games.proof-gatekeeper.v1" and "agent-games.preflight.v1"),
 * decides APPROVE / REJECT with deterministic checks only (lib/checks.js),
 * proves the decision with a local Groth16 proof (lib/circuit.js), and
 * returns a signed response. Fail closed on every error path.
 *
 * Binds localhost only (HOST env, default 127.0.0.1) — a public HTTPS
 * front (tunnel/reverse proxy) is a deployment step, see README.md.
 */
const http = require("node:http");
const { signBody, verifyBody } = require("./lib/hmac");
const { decide, missingFields } = require("./lib/checks");
const { buildCircuitInput, prove } = require("./lib/circuit");
const { SeenStore, ResponseCache } = require("./lib/store");
const kurier = require("./lib/kurier");

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 8787);
const MAX_BODY_BYTES = 1_000_000;
const REQUIRE_KURIER_FINALITY = process.env.REQUIRE_KURIER_FINALITY === "true";
const KURIER_BUDGET_MS = Number(process.env.KURIER_BUDGET_MS || 40000);

const seenStore = new SeenStore();
const responseCache = new ResponseCache();

function log(...args) {
  console.error(new Date().toISOString(), ...args);
}

/** Serialize + sign + send a JSON response. Returns the exact body sent. */
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": signBody(body),
  });
  res.end(body);
  return body;
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function handleGatekeeperTask(envelope) {
  const input = envelope.input;
  const verdict = decide(input, (tx) => seenStore.has(tx));
  const response = {
    decision: verdict.decision,
    reason_code: verdict.reason_code,
    proof_tx: input.proof_tx,
  };

  // PROOF_REUSED is the one rejection the circuit cannot prove (its fields
  // are all valid, so the circuit would only attest decision=1). The event
  // page confirms: "PROOF_REUSED tasks have no proof to submit".
  if (verdict.reason_code === "PROOF_REUSED") {
    return response;
  }

  // Isolated incoming-proof verification step (lib/kurier.js). By default
  // informational only; REQUIRE_KURIER_FINALITY=true makes an unfinalized
  // result fail closed (REJECT, unprovable — same shape as PROOF_REUSED).
  const verification = await kurier.verifyPaymentProof(input);
  if (REQUIRE_KURIER_FINALITY && verification.status !== "finalized") {
    log(`task ${envelope.task_id}: finality required but status=${verification.status}; failing closed`);
    return {
      decision: "REJECT",
      reason_code: "PROOF_NOT_FINALIZED", // not a spec code — see README gap #6
      proof_tx: input.proof_tx,
    };
  }

  // Prove the decision. The circuit enforces decision correctness, so a
  // prove() failure here means our encoding disagrees with the circuit —
  // fail closed rather than emit an unproven approval.
  const decisionBit = verdict.decision === "APPROVE" ? 1 : 0;
  try {
    const circuitInput = buildCircuitInput(input, envelope.task_id, decisionBit);
    const { proof, publicSignals } = await prove(circuitInput);
    response.proof = proof;
    response.public_signals = publicSignals;
  } catch (err) {
    log(`task ${envelope.task_id}: proof generation failed:`, err.message);
    if (verdict.decision === "APPROVE") {
      // Never emit an unproven APPROVE. Downgrade to an unproven REJECT
      // (reason code is not spec-defined for this path — README gap #7).
      return {
        decision: "REJECT",
        reason_code: "INTERNAL_ERROR",
        proof_tx: input.proof_tx,
      };
    }
    return response; // REJECT stands, just without its proof
  }

  if (verdict.decision === "APPROVE") {
    // Record the proof reference as seen ("accepted") before responding.
    seenStore.add(input.proof_tx);
  }

  // Optional audit path: submit our decision proof to Kurier (spec-exact
  // shape) and poll toward Finalized within a bounded budget. Failures
  // here never change the decision or the response.
  if (kurier.hasKey() && response.proof) {
    try {
      const job = await kurier.submitProofToKurier({
        proof: response.proof,
        publicSignals: response.public_signals,
      });
      const polled = await kurier.pollKurierJob(job, KURIER_BUDGET_MS);
      log(
        `task ${envelope.task_id}: kurier job=${JSON.stringify(polled.job)?.slice(0, 200)} finalized=${polled.finalized}${polled.note ? " note=" + polled.note : ""}`
      );
    } catch (err) {
      log(`task ${envelope.task_id}: kurier submission failed (ignored):`, err.message);
    }
  }

  return response;
}

async function handleRequest(req, res) {
  if (req.method === "GET" && req.url === "/health") {
    return sendJson(res, 200, { ok: true });
  }
  if (req.method !== "POST" || req.url !== "/agent") {
    return sendJson(res, 404, { error: "not_found" });
  }

  let raw;
  try {
    raw = await readRawBody(req);
  } catch (err) {
    return sendJson(res, 413, { error: "body_too_large" });
  }

  // 1. HMAC over the RAW body, BEFORE parsing (spec, Security checklist).
  const signature = req.headers["x-agent-games-signature"];
  if (!verifyBody(raw, signature)) {
    log("rejected request: bad or missing x-agent-games-signature");
    return sendJson(res, 401, { error: "invalid_signature" });
  }

  // 2. Parse.
  let envelope;
  try {
    envelope = JSON.parse(raw.toString("utf8"));
  } catch {
    return sendJson(res, 400, { error: "invalid_json" });
  }

  // 3. Preflight handshake (spec: reply { ok: true, protocolVersion: "v1" }).
  if (envelope && envelope.type === "agent-games.preflight.v1") {
    return sendJson(res, 200, { ok: true, protocolVersion: "v1" });
  }

  if (!envelope || envelope.type !== "agent-games.proof-gatekeeper.v1") {
    return sendJson(res, 400, { error: "unsupported_type" });
  }

  // 4. Idempotency: task IDs are idempotency keys (spec). A redelivery
  //    returns the cached response bytes verbatim.
  const taskId = envelope.task_id;
  if (typeof taskId !== "string" || !taskId) {
    return sendJson(res, 400, { error: "missing_task_id" });
  }
  const cached = responseCache.get(taskId);
  if (cached) {
    res.writeHead(cached.status, {
      "content-type": "application/json",
      "x-agent-games-signature": signBody(cached.body),
    });
    return res.end(cached.body);
  }

  // 5. Shape validation — a decision cannot be computed (or proven) from
  //    missing fields, so fail closed with a 400 rather than guessing.
  const missing = missingFields(envelope.input);
  if (missing.length > 0) {
    return sendJson(res, 400, { error: "malformed_task", missing });
  }

  // 6. Decide + prove + respond.
  try {
    const response = await handleGatekeeperTask(envelope);
    const body = sendJson(res, 200, response);
    responseCache.set(taskId, { status: 200, body });
  } catch (err) {
    log(`task ${taskId}: unhandled error:`, err.stack || err.message);
    // Fail closed: a REJECT with no proof, never an approval.
    const body = sendJson(res, 200, {
      decision: "REJECT",
      reason_code: "INTERNAL_ERROR", // not a spec code — see README gap #7
      proof_tx: envelope.input.proof_tx,
    });
    responseCache.set(taskId, { status: 200, body });
  }
}

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch((err) => {
    log("fatal handler error:", err.stack || err.message);
    try {
      sendJson(res, 500, { error: "internal_error" });
    } catch { /* socket already gone */ }
  });
});

// The platform's hard deadline is 60s; drop sockets that stall past it.
server.setTimeout(60_000);

server.listen(PORT, HOST, () => {
  log(`MAME97-GK gatekeeper listening on http://${HOST}:${PORT}/agent`);
  if (!process.env.AGENT_GAMES_HMAC_SECRET) {
    log("WARNING: AGENT_GAMES_HMAC_SECRET is not set — signature checks will throw");
  }
  log(`kurier: ${kurier.hasKey() ? "KURIER_API_KEY set" : "no KURIER_API_KEY (verification step skipped)"}`);
});
