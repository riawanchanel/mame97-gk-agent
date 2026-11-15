"use strict";
/**
 * Self-test for the MAME97-GK Proof Gatekeeper agent.
 *
 * Spawns the real server (dummy HMAC secret, throwaway stores) and checks:
 *   1. tampered body is rejected on signature (401)
 *   2. missing signature is rejected (401)
 *   3. preflight returns { ok: true, protocolVersion: "v1" }, signed
 *   4. synthetic VALID task -> APPROVE / VALID_CONDITION, with a real
 *      Groth16 proof that snarkjs verifies against the zkey's VK
 *   5. redelivery of the same task_id returns identical bytes (idempotency)
 *   6. same proof_tx under a new task_id -> REJECT / PROOF_REUSED, no proof
 *   7. VK trap -> REJECT / VK_SUBSTITUTION, proof verifies
 *   8. threshold trap -> REJECT / THRESHOLD_MISMATCH, proof verifies
 *   9. recipient trap -> REJECT / RECIPIENT_MISMATCH, proof verifies
 *  10. amount trap -> REJECT / AMOUNT_OVERFLOW, proof verifies
 *  11. expiry trap (current_block == expiry_block) -> REJECT /
 *      EXPIRED_CONDITION, proof verifies
 *
 * Run: npm test   (or: node selftest.js)
 */
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const snarkjs = require("snarkjs");

const SECRET = "selftest-dummy-secret";
const PORT = 18787;
const BASE = `http://127.0.0.1:${PORT}`;
const ZKEY = path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey");

const REGISTERED_VK =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const OTHER_VK =
  "0x13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa";
const RECIPIENT = "0x00000000000000000000000000000000de429f01";
const OTHER_RECIPIENT = "0x00000000000000000000000000000000beefbeef";

let failures = 0;
function check(label, cond, extra = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}${extra ? " — " + extra : ""}`);
  if (!cond) failures++;
}

function sign(rawBody) {
  return crypto.createHmac("sha256", SECRET).update(rawBody).digest("hex");
}

function verifyResponseSignature(rawBody, header) {
  return header === sign(rawBody);
}

async function post(pathname, rawBody, headers = {}) {
  const res = await fetch(BASE + pathname, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: rawBody,
  });
  const text = await res.text();
  return {
    status: res.status,
    text,
    json: (() => { try { return JSON.parse(text); } catch { return null; } })(),
    signature: res.headers.get("x-agent-games-signature"),
  };
}

function signedPost(pathname, obj) {
  const raw = JSON.stringify(obj);
  return post(pathname, raw, { "x-agent-games-signature": sign(raw) });
}

function makeTask(overrides = {}, inputOverrides = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_selftest_" + crypto.randomBytes(4).toString("hex"),
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60_000).toISOString(),
    input: {
      registered_vk: REGISTERED_VK,
      proof_vk: REGISTERED_VK,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0x" + crypto.randomBytes(32).toString("hex"),
      ...inputOverrides,
    },
    ...overrides,
  };
}

async function waitForServer(child) {
  let buf = "";
  child.stderr.on("data", (d) => { buf += d.toString(); });
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (buf.includes("listening")) return;
    if (child.exitCode !== null) throw new Error("server exited early:\n" + buf);
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("server did not start in time:\n" + buf);
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "gk-selftest-"));
  const child = spawn(process.execPath, [path.join(__dirname, "server.js")], {
    env: {
      ...process.env,
      AGENT_GAMES_HMAC_SECRET: SECRET,
      HOST: "127.0.0.1",
      PORT: String(PORT),
      SEEN_STORE_PATH: path.join(tmp, "seen.json"),
      RESPONSE_CACHE_PATH: path.join(tmp, "responses.json"),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForServer(child);
    const vk = await snarkjs.zKey.exportVerificationKey(ZKEY);

    // 1. Tampered body -> 401
    {
      const task = makeTask();
      const raw = JSON.stringify(task);
      const tampered = raw.replace('"500"', '"501"');
      const r = await post("/agent", tampered, { "x-agent-games-signature": sign(raw) });
      check("tampered body rejected (401)", r.status === 401, `status=${r.status}`);
    }

    // 2. Missing signature -> 401
    {
      const r = await post("/agent", JSON.stringify(makeTask()));
      check("missing signature rejected (401)", r.status === 401, `status=${r.status}`);
    }

    // 3. Preflight
    {
      const r = await signedPost("/agent", {
        type: "agent-games.preflight.v1",
        agent_id: "agt_selftest",
        issued_at: new Date().toISOString(),
        nonce: "abc123",
      });
      check(
        "preflight ok + protocolVersion v1",
        r.status === 200 && r.json?.ok === true && r.json?.protocolVersion === "v1",
        `status=${r.status} body=${r.text}`
      );
      check("preflight response signed", verifyResponseSignature(r.text, r.signature));
    }

    // 4. VALID task -> APPROVE with a locally verifiable proof
    const validTask = makeTask();
    const validRaw = JSON.stringify(validTask);
    const validRes = await post("/agent", validRaw, {
      "x-agent-games-signature": sign(validRaw),
    });
    check("valid task HTTP 200", validRes.status === 200, `status=${validRes.status}`);
    check(
      "valid task APPROVE / VALID_CONDITION",
      validRes.json?.decision === "APPROVE" && validRes.json?.reason_code === "VALID_CONDITION",
      `body=${validRes.text.slice(0, 160)}`
    );
    check("valid task response signed", verifyResponseSignature(validRes.text, validRes.signature));
    {
      const ok = await snarkjs.groth16.verify(
        vk,
        validRes.json.public_signals,
        validRes.json.proof
      );
      check("valid task proof verifies against zkey VK", ok === true);
      check(
        "public_signals: 13 entries, decision echo = 1",
        Array.isArray(validRes.json.public_signals) &&
          validRes.json.public_signals.length === 13 &&
          validRes.json.public_signals[11] === "1",
        `signals=${validRes.json.public_signals?.length}`
      );
    }

    // 5. Idempotent redelivery -> identical bytes
    {
      const r = await post("/agent", validRaw, {
        "x-agent-games-signature": sign(validRaw),
      });
      check("redelivery returns identical response bytes", r.text === validRes.text);
    }

    // 6. PROOF_REUSED: same proof_tx, new task_id
    {
      const reused = makeTask({}, { proof_tx: validTask.input.proof_tx });
      const r = await signedPost("/agent", reused);
      check(
        "reused proof_tx -> REJECT / PROOF_REUSED",
        r.json?.decision === "REJECT" && r.json?.reason_code === "PROOF_REUSED",
        `body=${r.text.slice(0, 160)}`
      );
      check("reused response carries no proof", !("proof" in (r.json ?? {})));
    }

    // 7-11. Trap tasks: REJECT with the right code and a verifiable proof
    const traps = [
      ["VK trap", { proof_vk: OTHER_VK }, "VK_SUBSTITUTION"],
      ["threshold trap", { public_balance: "999" }, "THRESHOLD_MISMATCH"],
      ["recipient trap", { recipient: OTHER_RECIPIENT }, "RECIPIENT_MISMATCH"],
      ["amount trap", { amount: "1001" }, "AMOUNT_OVERFLOW"],
      ["expiry trap (current == expiry)", { current_block: 8430000 }, "EXPIRED_CONDITION"],
    ];
    for (const [label, inputOverrides, expectedCode] of traps) {
      const r = await signedPost("/agent", makeTask({}, inputOverrides));
      check(
        `${label} -> REJECT / ${expectedCode}`,
        r.json?.decision === "REJECT" && r.json?.reason_code === expectedCode,
        `body=${r.text.slice(0, 140)}`
      );
      const ok = r.json?.proof
        ? await snarkjs.groth16.verify(vk, r.json.public_signals, r.json.proof)
        : false;
      check(`${label} proof verifies, decision echo = 0`,
        ok === true && r.json.public_signals?.[11] === "0");
    }
  } finally {
    child.kill("SIGTERM");
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("SELFTEST ERROR:", err);
  process.exit(1);
});
