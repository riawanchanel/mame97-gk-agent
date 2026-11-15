"use strict";
/**
 * File-backed stores:
 *  - SeenStore: proof_tx references this agent has APPROVED (reuse trap).
 *  - ResponseCache: task_id -> exact response (idempotent redelivery).
 *
 * Both persist as JSON files, written atomically (tmp file + rename), and
 * are loaded at boot. Paths are env-overridable:
 *   SEEN_STORE_PATH     (default <agent>/data/seen-proofs.json)
 *   RESPONSE_CACHE_PATH (default <agent>/data/responses.json)
 */
const fs = require("node:fs");
const path = require("node:path");

function loadJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function saveJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data));
  fs.renameSync(tmp, file);
}

class SeenStore {
  constructor(file) {
    this.file =
      file ||
      process.env.SEEN_STORE_PATH ||
      path.join(__dirname, "..", "data", "seen-proofs.json");
    this.set = new Set(loadJson(this.file, []));
  }
  has(proofTx) {
    return this.set.has(proofTx);
  }
  add(proofTx) {
    if (this.set.has(proofTx)) return;
    this.set.add(proofTx);
    saveJson(this.file, [...this.set]);
  }
}

class ResponseCache {
  constructor(file) {
    this.file =
      file ||
      process.env.RESPONSE_CACHE_PATH ||
      path.join(__dirname, "..", "data", "responses.json");
    this.map = new Map(Object.entries(loadJson(this.file, {})));
  }
  get(taskId) {
    return this.map.get(taskId);
  }
  set(taskId, entry) {
    this.map.set(taskId, entry);
    saveJson(this.file, Object.fromEntries(this.map));
  }
}

module.exports = { SeenStore, ResponseCache };
