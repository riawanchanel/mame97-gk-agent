"use strict";
/**
 * HMAC signing / verification for Agent Games envelopes.
 *
 * Spec (/build, Agent interface + Security checklist):
 *  - "compute the HMAC over the RAW request body and compare it to the
 *    x-agent-games-signature header BEFORE parsing JSON. Reject on mismatch."
 *  - "Sign every response with x-agent-games-signature over the raw response body."
 *
 * SPEC GAP: the /build page never states the HMAC algorithm or the digest
 * encoding. Default here is HMAC-SHA256, hex digest (the overwhelmingly common
 * convention). Both are overridable via env:
 *   AGENT_GAMES_HMAC_ALGORITHM (default "sha256")
 *   AGENT_GAMES_HMAC_ENCODING  (default "hex"; inbound verification also
 *                               accepts base64 as a fallback, both compared
 *                               in constant time)
 */
const crypto = require("node:crypto");

const ALGORITHM = process.env.AGENT_GAMES_HMAC_ALGORITHM || "sha256";
const ENCODING = process.env.AGENT_GAMES_HMAC_ENCODING || "hex";

function getSecret() {
  const s = process.env.AGENT_GAMES_HMAC_SECRET;
  if (!s) throw new Error("AGENT_GAMES_HMAC_SECRET is not set");
  return s;
}

/** Sign a raw body (Buffer or string) and return the digest string. */
function signBody(rawBody) {
  return crypto
    .createHmac(ALGORITHM, getSecret())
    .update(rawBody)
    .digest(ENCODING);
}

function timingSafeStringEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/**
 * Verify an inbound x-agent-games-signature header against the raw body.
 * Tries the configured encoding first, then the other common encoding.
 */
function verifyBody(rawBody, headerValue) {
  if (!headerValue || typeof headerValue !== "string") return false;
  const expectedHex = crypto
    .createHmac(ALGORITHM, getSecret())
    .update(rawBody)
    .digest("hex");
  const expectedB64 = crypto
    .createHmac(ALGORITHM, getSecret())
    .update(rawBody)
    .digest("base64");
  const provided = headerValue.trim();
  return (
    timingSafeStringEqual(provided, expectedHex) ||
    timingSafeStringEqual(provided, expectedB64)
  );
}

module.exports = { signBody, verifyBody, ALGORITHM, ENCODING };
