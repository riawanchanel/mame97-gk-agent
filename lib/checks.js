"use strict";
/**
 * Deterministic decision checks — plain code, no model involvement.
 *
 * Mirrors the /build Security checklist and the event page's trap
 * encyclopedia 1:1, in checklist order; the FIRST failing check names the
 * reason_code:
 *
 *   1. VK_SUBSTITUTION    proof_vk != registered_vk
 *        ("The verification key matches the key registered for this condition")
 *   2. THRESHOLD_MISMATCH public_balance < minimum
 *        ("public threshold meets the minimum" — event page)
 *   3. RECIPIENT_MISMATCH recipient != condition_recipient
 *   4. AMOUNT_OVERFLOW    amount > max_transfer
 *        ("Approve only up to the cap; reject the rest" — event page)
 *   5. EXPIRED_CONDITION  current_block >= expiry_block
 *        (the circuit enforces currentBlock < expiryBlock STRICTLY —
 *         probed empirically: currentBlock == expiryBlock cannot prove an
 *         approval, so at-block already counts as expired)
 *   6. PROOF_REUSED       proof_tx already in the seen set (checked last:
 *        it is the only trap whose fields are all valid, and the only one
 *        that cannot carry a Groth16 proof — see circuit.js)
 *
 * Equality checks (VK, recipient) compare the ENCODED field elements, not
 * the raw strings, so the plain-code verdict always agrees with the
 * circuit's enforced verdict for the same inputs.
 *
 * Seen-set semantics (event page, PROOF_REUSED): "The proof reference was
 * already accepted in a previous task" — a reference is recorded as seen
 * when this agent APPROVES a task carrying it. References on rejected
 * tasks are not recorded.
 */
const { toFieldElement } = require("./circuit");

const REASON = {
  VALID: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  PROOF_REUSED: "PROOF_REUSED",
};

function big(value) {
  return BigInt(toFieldElement(value));
}

/**
 * @param {object} input  envelope.input of a proof-gatekeeper task
 * @param {(proofTx:string)=>boolean} isSeen  seen-set lookup
 * @returns {{decision:"APPROVE"|"REJECT", reason_code:string, fieldTrap:boolean}}
 *   fieldTrap=true means the rejection is provable by the circuit
 *   (decision=0 satisfies its assert). PROOF_REUSED is the only
 *   non-field trap.
 */
function decide(input, isSeen) {
  if (big(input.proof_vk) !== big(input.registered_vk)) {
    return { decision: "REJECT", reason_code: REASON.VK_SUBSTITUTION, fieldTrap: true };
  }
  if (big(input.public_balance) < big(input.minimum)) {
    return { decision: "REJECT", reason_code: REASON.THRESHOLD_MISMATCH, fieldTrap: true };
  }
  if (big(input.recipient) !== big(input.condition_recipient)) {
    return { decision: "REJECT", reason_code: REASON.RECIPIENT_MISMATCH, fieldTrap: true };
  }
  if (big(input.amount) > big(input.max_transfer)) {
    return { decision: "REJECT", reason_code: REASON.AMOUNT_OVERFLOW, fieldTrap: true };
  }
  if (big(input.current_block) >= big(input.expiry_block)) {
    return { decision: "REJECT", reason_code: REASON.EXPIRED_CONDITION, fieldTrap: true };
  }
  if (typeof input.proof_tx === "string" && isSeen(input.proof_tx)) {
    return { decision: "REJECT", reason_code: REASON.PROOF_REUSED, fieldTrap: false };
  }
  return { decision: "APPROVE", reason_code: REASON.VALID, fieldTrap: false };
}

/** Fields the envelope must carry for a decision to be computable at all. */
const REQUIRED_INPUT_FIELDS = [
  "registered_vk",
  "proof_vk",
  "minimum",
  "public_balance",
  "expiry_block",
  "current_block",
  "recipient",
  "condition_recipient",
  "amount",
  "max_transfer",
  "proof_tx",
];

function missingFields(input) {
  if (!input || typeof input !== "object") return REQUIRED_INPUT_FIELDS.slice();
  return REQUIRED_INPUT_FIELDS.filter(
    (f) => input[f] === undefined || input[f] === null || input[f] === ""
  );
}

module.exports = { decide, missingFields, REASON };
