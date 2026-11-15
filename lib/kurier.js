"use strict";
/**
 * Kurier (zkVerify) integration — ISOLATED verification step.
 *
 * What the spec (/build section 03) actually pins down, verbatim in shape:
 *
 *   const API_URL = "https://api.kurier.xyz/api/v1";
 *   POST `${API_URL}/submit-proof/${KURIER_API_KEY}`
 *     { proofType: "groth16",
 *       vkRegistered: true,
 *       proofOptions: { library: "snarkjs", curve: "bn128" },
 *       proofData: { proof, publicSignals, vk: registeredVkHash } }
 *   Job states: Submitted -> IncludedInBlock -> Finalized
 *   ("Safe to return as confirmed" at Finalized)
 *
 * and the gatekeeper circuit's registered vk hash:
 *   0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
 *   (also served from the platform's /api/circuit-info)
 *
 * What the spec does NOT pin down (gaps, see README):
 *  - No poll/status endpoint shape is given for a submitted job. pollKurierJob
 *    therefore only works if KURIER_JOB_STATUS_URL_TEMPLATE is configured
 *    (a URL containing "{jobId}"); otherwise it returns the submit response
 *    as-is and reports polling as unconfigured. Nothing is invented.
 *  - No Kurier call shape is given for reading back the INCOMING payment
 *    proof (the task's proof_tx) either. verifyPaymentProof() below is the
 *    isolated seam for that step: without a key it is skipped, and with a
 *    key it still has no spec-defined endpoint to call, so it reports
 *    "no_spec_endpoint" instead of guessing. The deterministic envelope
 *    checks in checks.js cover every documented trap type (all seven are
 *    field/seen-set mismatches); if a future spec adds a finality trap,
 *    wire it in here and set REQUIRE_KURIER_FINALITY=true to fail closed
 *    until this function returns "finalized".
 */

const KURIER_API_URL = process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1";
const GATEKEEPER_VK_HASH =
  process.env.GATEKEEPER_VK_HASH ||
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const POLL_TEMPLATE = process.env.KURIER_JOB_STATUS_URL_TEMPLATE || "";
const POLL_INTERVAL_MS = Number(process.env.KURIER_POLL_INTERVAL_MS || 5000);

function hasKey() {
  return Boolean(process.env.KURIER_API_KEY);
}

async function fetchJson(url, options, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* keep raw text */ }
    return { status: res.status, json, text };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Submit one of OUR gatekeeper decision proofs to Kurier for zkVerify
 * verification, using exactly the request shape from the /build sample.
 * Returns the parsed job object (whatever fields Kurier returns).
 */
async function submitProofToKurier({ proof, publicSignals }, timeoutMs = 15000) {
  if (!hasKey()) return { skipped: true, reason: "no KURIER_API_KEY configured" };
  const { status, json, text } = await fetchJson(
    `${KURIER_API_URL}/submit-proof/${process.env.KURIER_API_KEY}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: GATEKEEPER_VK_HASH },
      }),
    },
    timeoutMs
  );
  if (status < 200 || status >= 300) {
    throw new Error(`Kurier submit-proof HTTP ${status}: ${text.slice(0, 200)}`);
  }
  return json ?? { raw: text };
}

function extractJobId(job) {
  if (!job || typeof job !== "object") return null;
  return job.jobId || job.id || job.job_id || null;
}

function extractJobStatus(job) {
  if (!job || typeof job !== "object") return null;
  return job.status || job.state || null;
}

/**
 * Poll a Kurier job until Finalized or the budget runs out.
 * INERT unless KURIER_JOB_STATUS_URL_TEMPLATE is set (spec gap — the /build
 * page names the states but never gives the status endpoint).
 */
async function pollKurierJob(job, budgetMs = 40000) {
  const jobId = extractJobId(job);
  if (!jobId) return { job, finalized: false, note: "submit response carried no job id" };
  if (!POLL_TEMPLATE) {
    return {
      job,
      finalized: extractJobStatus(job) === "Finalized",
      note: "KURIER_JOB_STATUS_URL_TEMPLATE not set; polling disabled (spec gives no status endpoint)",
    };
  }
  const url = POLL_TEMPLATE.replace("{jobId}", encodeURIComponent(jobId));
  const deadline = Date.now() + budgetMs;
  let last = job;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    const { json } = await fetchJson(url, { method: "GET" }, 10000);
    if (json) last = json;
    if (extractJobStatus(last) === "Finalized") return { job: last, finalized: true };
  }
  return { job: last, finalized: false, note: "poll budget exhausted before Finalized" };
}

/**
 * ISOLATED verification step for the incoming payment proof (task proof_tx).
 * See the header comment: the spec defines no Kurier read/submit shape for
 * someone else's already-submitted proof, so this never invents one.
 *
 * @returns {Promise<{status: "skipped_no_key"|"no_spec_endpoint", detail: string}>}
 */
async function verifyPaymentProof(/* taskInput */) {
  if (!hasKey()) {
    return {
      status: "skipped_no_key",
      detail:
        "KURIER_API_KEY not configured; incoming-proof finality not checked. " +
        "Decision rests on the deterministic envelope checks (all seven documented trap types are field/seen-set mismatches).",
    };
  }
  return {
    status: "no_spec_endpoint",
    detail:
      "KURIER_API_KEY is set, but the /build spec defines no Kurier call shape for verifying an incoming proof_tx; " +
      "refusing to invent one. Decision rests on the deterministic envelope checks.",
  };
}

module.exports = {
  KURIER_API_URL,
  GATEKEEPER_VK_HASH,
  hasKey,
  submitProofToKurier,
  pollKurierJob,
  verifyPaymentProof,
};
