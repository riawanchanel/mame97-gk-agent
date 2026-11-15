# MAME97-GK — Proof Gatekeeper Agent

HTTP service for the zkVerify **Agent Games — Proof Gatekeeper** track.
Receives signed task envelopes, decides APPROVE / REJECT with deterministic
checks only (no model ever decides), proves the decision with a local
Groth16 proof (snarkjs + the official `gatekeeper` circuit), and returns a
signed response.

Implements the protocol in `../build-spec.txt` (the official /build page):
HMAC over the raw body before parsing, preflight handshake, the Security
checklist, trap reason codes from the event page's trap encyclopedia, and
the Kurier submission shape from the /build code sample.

## Run

```bash
cd ~/workspace/agentgames/agent
npm install
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET (see below)
set -a; . ./.env; set +a
npm start              # node server.js
npm test               # self-test with a dummy secret (safe to run anytime)
```

- Listens on `HOST:PORT` (default `127.0.0.1:8787`), path **`POST /agent`**
  (register the full path, not the root), plus unsigned-path `GET /health`
  (its JSON body is still HMAC-signed like every response).
- Node.js v22+ (developed on v24). Dependencies: `snarkjs`, `js-sha3`.
- Circuit artifacts are read from `../../circuits/gatekeeper.wasm` and
  `gatekeeper_final.zkey` (override with `GATEKEEPER_WASM` / `GATEKEEPER_ZKEY`).
- State lives in `data/` (`seen-proofs.json`, `responses.json`), both
  file-backed and written atomically; override with `SEEN_STORE_PATH` /
  `RESPONSE_CACHE_PATH`.

## What the platform still needs (not done by this code)

1. **A public HTTPS endpoint, up 24/7.** This service binds localhost only.
   Put it behind a tunnel / reverse proxy / host with a public HTTPS URL
   and register that URL **with the full `/agent` path** on the dashboard.
   (Hosting choice is still open — see `../STATE.md`.)
2. **The real HMAC secret.** Dashboard → My Agents → MAME97-GK →
   *Rotate Secret* → copy the one-time plaintext into
   `AGENT_GAMES_HMAC_SECRET`, restart the service, then let the platform
   run **preflight** — it must pass before the agent is marked active.
   A placeholder secret fails preflight with a signature error.
3. **GitHub account linked** in the site's Settings (the dashboard refuses
   agent registration with a repository until GitHub is linked), and the
   agent registered for the *Proof Gatekeeper* event.
4. **Practice mode first** — at least one practice task is required before
   scored rounds, and all seven trap types are reproducible there.
5. **Optional: a Kurier mainnet API key** in `KURIER_API_KEY` if our
   decision proofs should also be submitted to zkVerify via Kurier
   (the response proof is verified by the platform either way).

## How a task is handled

1. Raw body read (≤1 MB) → **HMAC verified before parsing** → 401 on mismatch.
2. `agent-games.preflight.v1` → `{ ok: true, protocolVersion: "v1" }`, signed.
3. `task_id` idempotency: a redelivery returns the cached response bytes
   verbatim (in-memory + file-backed).
4. Deterministic checks (`lib/checks.js`), first failure wins, in the
   Security-checklist order:
   `VK_SUBSTITUTION` → `THRESHOLD_MISMATCH` → `RECIPIENT_MISMATCH` →
   `AMOUNT_OVERFLOW` → `EXPIRED_CONDITION` → `PROOF_REUSED`; otherwise
   APPROVE with reason_code `VALID_CONDITION`.
5. The decision is proven with snarkjs `fullProve` (fast, ~0.3 s locally).
   The circuit itself enforces decision correctness (see gap #1), so a
   proof can only ever attest the correct decision for the given fields.
   `PROOF_REUSED` is the one answer that carries **no** proof — its fields
   are all valid, so the circuit could only prove APPROVE; the event page
   confirms PROOF_REUSED tasks "have no proof to submit".
   A proof reference is recorded as *seen* when a task carrying it is
   APPROVED ("already accepted in a previous task" — event page).
6. Every response is signed: `x-agent-games-signature` = HMAC over the raw
   response body. Fail closed everywhere: bad signature, malformed task,
   proof failure, or internal error never produce an approval.

## Live vs stubbed

| Piece | Status |
|---|---|
| HMAC verify/sign, preflight, idempotency | **Live** (spec-exact) |
| Decision checks (all 7 trap types) | **Live** (spec + circuit-verified boundaries) |
| Groth16 proof generation (snarkjs, official artifacts) | **Live** — proofs verify against the zkey's VK (self-test) |
| Kurier **submission** of our decision proof | **Live when `KURIER_API_KEY` is set**, using the exact request shape from the /build sample; failures are logged and never change the response |
| Kurier job **polling** to Finalized | **Stubbed/inert** — spec names the states but gives no status endpoint (gap #4); activates only if `KURIER_JOB_STATUS_URL_TEMPLATE` is configured |
| Incoming payment-proof verification (`verifyPaymentProof`) | **Isolated stub** — spec gives no call shape for it (gap #5); returns `skipped_no_key` / `no_spec_endpoint`. Set `REQUIRE_KURIER_FINALITY=true` to fail closed until it can return `finalized` |

## Spec gaps found (and the reading implemented)

1. **The circuit's input mapping is nowhere in the spec.** /build never
   names the gatekeeper circuit's input signals, public signals, or the
   decision encoding. Recovered empirically from the official artifacts
   (2026-11-15, wasm input-table probe + witness inspection + boundary
   probes; full method documented in `lib/circuit.js` at
   `CIRCUIT_INPUT_MAPPING` — the one configurable place):
   13 scalar inputs `taskId, registeredVkHash, proofVkHash, minimum,
   publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
   amount, maxTransfer, decision, salt`; 13 public signals = one commitment
   hash output (varies with `taskId` and the private `salt`) + every input
   except `salt` echoed in input order; `decision` 1 = APPROVE / 0 = REJECT
   is **enforced** by the circuit (`GatekeeperEvaluation` assert).
2. **task_id → field element encoding is unspecified.** Sample task_ids are
   strings (`"gk_8d31_..."`), but the circuit takes one field element.
   Default here: `keccak256(utf8(task_id)) mod Fr`
   (`GATEKEEPER_TASK_ID_ENCODING=keccak256|sha256`, or numeric passthrough
   for numeric ids).
3. **HMAC algorithm / digest encoding are unspecified.** Default
   HMAC-SHA256, hex (`AGENT_GAMES_HMAC_ALGORITHM`,
   `AGENT_GAMES_HMAC_ENCODING`). Inbound verification also accepts a base64
   digest; both are compared in constant time.
4. **No Kurier poll endpoint.** The /build page lists job states
   (Submitted → IncludedInBlock → Finalized) but never the status URL, so
   polling is not invented — see the table above.
5. **No verification shape for the incoming proof.** The Security checklist
   demands the incoming proof be confirmed on zkVerify, and the event-page
   checklist says "Call zkVerifyJS to confirm the proof is on-chain", but
   neither source gives a Kurier/zkVerifyJS call shape for a proof someone
   else submitted. Isolated as `verifyPaymentProof()` in `lib/kurier.js`.
   Note all seven documented trap types are envelope field / seen-set
   mismatches, so the deterministic checks classify every documented case.
6. **"Finalized before approval" is not implementable from the spec**
   (consequence of #4/#5). `REQUIRE_KURIER_FINALITY=true` fails closed
   with reason_code `PROOF_NOT_FINALIZED` — **not a spec code**.
7. **No reason codes exist for internal failures.** On the (should-never-
   happen) path where an APPROVE cannot be proven, the agent fails closed
   to REJECT with reason_code `INTERNAL_ERROR` — **not a spec code** —
   rather than emit an unproven approval.
8. **Expiry boundary contradicts the prose.** The event page says a
   condition is expired when its "block-height expiry has passed", but the
   circuit enforces `currentBlock < expiryBlock` strictly: at
   `currentBlock == expiryBlock` an approval is unprovable. This code
   follows the circuit (`EXPIRED_CONDITION` when
   `current_block >= expiry_block`).
   Threshold and cap boundaries follow the prose and the circuit agrees:
   `public_balance == minimum` passes, `amount == max_transfer` passes.
9. **Reason-code precedence is unspecified** when several traps coincide;
   the first failure in Security-checklist order is returned.
10. **The spec's sample response omits the proof** (`{decision,
    reason_code, proof_tx}`), while architecture step 05 requires the
    proof + public_signals "on every provable task" and the score model
    charges −2 for a missing/invalid proof. We include `proof` and
    `public_signals` whenever the circuit can prove the decision, and echo
    the task's `proof_tx` (as the sample response does).
11. **Timestamp validation is unspecified** (no clock-skew tolerance for
    `issued_at` / `deadline_at`). The server does not reject on timestamps;
    the platform enforces the 60-second deadline itself.

## Self-test

`npm test` spawns the real server with a dummy secret and throwaway stores
and verifies: signature rejection on a tampered body and on a missing
signature, the preflight reply + its signature, an APPROVE for a synthetic
valid task whose proof **verifies locally against the zkey's exported
verification key**, byte-identical idempotent redelivery, a PROOF_REUSED
rejection with no proof, and all five field traps rejecting with their
expected reason codes and locally verifiable proofs. Latest run: **21/21
checks PASS** (2026-11-15).
