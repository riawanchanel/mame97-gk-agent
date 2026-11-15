"use strict";
/**
 * Gatekeeper circuit: input mapping + local Groth16 proving with snarkjs.
 *
 * ============================================================================
 * CIRCUIT_INPUT_MAPPING  —  THE ONE CLEARLY-MARKED MAPPING PLACE
 * ============================================================================
 * The /build page NEVER names the circuit's input signals (spec gap #1 in
 * README.md). The mapping below was recovered empirically from the official
 * artifacts (gatekeeper.wasm / gatekeeper_final.zkey) on 2026-11-15:
 *
 *  - The wasm's input-signal table (probed via getInputSignalSize over an
 *    fnv1a dictionary) contains EXACTLY 13 scalar inputs; getInputSize() = 13:
 *      taskId, registeredVkHash, proofVkHash, minimum, publicBalance,
 *      expiryBlock, currentBlock, recipient, conditionRecipient, amount,
 *      maxTransfer, decision, salt
 *  - The verification key has 14 IC points => 13 public signals. A witness
 *    with distinctive values shows the public signals are, in order:
 *      [0]  commitmentHash  (circuit output; Poseidon-style hash that varies
 *                            with taskId and salt)
 *      [1]  registeredVkHash   [2] proofVkHash     [3] minimum
 *      [4]  publicBalance      [5] expiryBlock     [6] currentBlock
 *      [7]  recipient          [8] conditionRecipient
 *      [9]  amount             [10] maxTransfer    [11] decision
 *      [12] taskId
 *    i.e. every input except the private `salt` is echoed as a public signal.
 *  - The circuit ENFORCES the decision (template GatekeeperEvaluation,
 *    assert ~line 102): proving fails unless
 *        decision == 1  iff  ALL of
 *          proofVkHash == registeredVkHash,
 *          publicBalance >= minimum            (equality passes — probed),
 *          recipient == conditionRecipient,
 *          amount <= maxTransfer               (equality passes — probed),
 *          currentBlock <  expiryBlock         (STRICT — equality FAILS,
 *                                               probed: at-block is expired)
 *        decision == 0  otherwise, and decision must be 0 or 1.
 *    So decision: 1 = APPROVE, 0 = REJECT, and a proof can only ever attest
 *    the CORRECT decision for the field values fed in. (This is why a
 *    PROOF_REUSED rejection cannot carry a proof: its fields are all valid,
 *    so the circuit would only prove decision = 1. The event page agrees:
 *    "PROOF_REUSED tasks have no proof to submit and are excluded.")
 *
 * Field-element encodings (all values are BN128 Fr elements):
 *  - 0x-prefixed hex strings  -> BigInt(hex) mod Fr   (VK hashes, addresses)
 *  - decimal strings / numbers -> BigInt(value)      (amounts, blocks)
 *  - task_id is a non-numeric string ("gk_8d31_...") in every spec sample,
 *    so it is hashed: taskId = keccak256(utf8(task_id)) mod Fr.
 *    THIS ENCODING IS A BEST READING, NOT SPEC TEXT — the spec never says
 *    how task_id becomes a field element. Change TASK_ID_ENCODING below
 *    ("keccak256" | "sha256" | "numeric-or-throw") in this one place if the
 *    platform ever documents the real mapping.
 *  - salt: fresh random field element per proof (private input; blinding
 *    for the commitment hash). Any value works; it never leaves the agent.
 * ============================================================================
 */
const crypto = require("node:crypto");
const path = require("node:path");
const { keccak256 } = require("js-sha3");
const snarkjs = require("snarkjs");

const FR = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

const TASK_ID_ENCODING = process.env.GATEKEEPER_TASK_ID_ENCODING || "keccak256";

const WASM_PATH =
  process.env.GATEKEEPER_WASM ||
  path.join(__dirname, "..", "..", "circuits", "gatekeeper.wasm");
const ZKEY_PATH =
  process.env.GATEKEEPER_ZKEY ||
  path.join(__dirname, "..", "..", "circuits", "gatekeeper_final.zkey");

/** Reduce a BigInt into the BN128 scalar field. */
function modFr(x) {
  const r = x % FR;
  return r >= 0n ? r : r + FR;
}

/**
 * Encode any envelope value as a field element (decimal string out).
 *  - "0x..." hex string -> BigInt(hex) mod Fr
 *  - decimal string / number / bigint -> BigInt mod Fr
 *  - any other string -> keccak256(utf8) mod Fr
 */
function toFieldElement(value) {
  if (typeof value === "bigint") return modFr(value).toString(10);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite numeric field");
    return modFr(BigInt(Math.trunc(value))).toString(10);
  }
  if (typeof value === "string") {
    const v = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(v)) return modFr(BigInt(v)).toString(10);
    if (/^[0-9]+$/.test(v)) return modFr(BigInt(v)).toString(10);
    return modFr(BigInt("0x" + keccak256(v))).toString(10);
  }
  throw new Error(`cannot encode field element from ${typeof value}`);
}

/** Encode the envelope task_id string as the circuit's taskId input. */
function encodeTaskId(taskId) {
  const s = String(taskId);
  if (/^[0-9]+$/.test(s)) return modFr(BigInt(s)).toString(10);
  if (/^0x[0-9a-fA-F]+$/.test(s)) return modFr(BigInt(s)).toString(10);
  if (TASK_ID_ENCODING === "sha256") {
    const h = crypto.createHash("sha256").update(s, "utf8").digest("hex");
    return modFr(BigInt("0x" + h)).toString(10);
  }
  // default: keccak256
  return modFr(BigInt("0x" + keccak256(s))).toString(10);
}

function randomSalt() {
  return modFr(BigInt("0x" + crypto.randomBytes(32).toString("hex"))).toString(10);
}

/**
 * Build the circuit input object from a task envelope input + decision.
 * Keys are the circuit's signal names (see CIRCUIT_INPUT_MAPPING above).
 */
function buildCircuitInput(taskInput, taskId, decision /* 0 | 1 */) {
  return {
    taskId: encodeTaskId(taskId),
    registeredVkHash: toFieldElement(taskInput.registered_vk),
    proofVkHash: toFieldElement(taskInput.proof_vk),
    minimum: toFieldElement(taskInput.minimum),
    publicBalance: toFieldElement(taskInput.public_balance),
    expiryBlock: toFieldElement(taskInput.expiry_block),
    currentBlock: toFieldElement(taskInput.current_block),
    recipient: toFieldElement(taskInput.recipient),
    conditionRecipient: toFieldElement(taskInput.condition_recipient),
    amount: toFieldElement(taskInput.amount),
    maxTransfer: toFieldElement(taskInput.max_transfer),
    decision: String(decision),
    salt: randomSalt(),
  };
}

/** Generate a real Groth16 proof locally. Returns { proof, publicSignals }. */
async function prove(circuitInput) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH
  );
  return { proof, publicSignals };
}

module.exports = {
  FR,
  WASM_PATH,
  ZKEY_PATH,
  toFieldElement,
  encodeTaskId,
  buildCircuitInput,
  prove,
};
