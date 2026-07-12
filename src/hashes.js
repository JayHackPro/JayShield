/*!
 * JayShield by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JayShield
 */

import crypto from "node:crypto";

/**
 * Known-bad file hashes. Signature rules catch families and copies; an exact
 * hash catches a specific known file with no false positives at all. The set
 * ships small and is meant to grow, and a team can extend it at runtime with
 * --hashes myfile.txt (one "sha256  label" per line).
 *
 * The seed entry is the EICAR test file, the harmless string the whole
 * industry uses to prove a scanner is wired up correctly.
 */
export const KNOWN_BAD = new Map([
  [
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    { name: "EICAR antivirus test file", severity: "medium", category: "test" }
  ]
]);

/** SHA-256 of a buffer, lowercase hex. */
export function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

/**
 * Look a file's hash up in the known-bad set (plus any extra entries loaded
 * from a user file). Returns a finding-shaped object or null.
 */
export function matchHash(buffer, extra) {
  const digest = sha256(buffer);
  const hit = (extra && extra.get(digest)) || KNOWN_BAD.get(digest);
  if (!hit) return null;
  return {
    id: "hash.known_bad",
    name: hit.name || "Known-bad file",
    severity: hit.severity || "critical",
    category: hit.category || "known",
    line: 1,
    evidence: `sha256:${digest}`,
    description: "This file matches a known-bad hash exactly, an unambiguous detection."
  };
}

/**
 * Parse an extra hash list. Each non-empty, non-comment line is a lowercase
 * sha256, optional whitespace, then an optional label.
 */
export function parseHashList(text) {
  const map = new Map();
  for (const rawLine of String(text).split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = line.match(/^([0-9a-f]{64})(?:\s+(.*))?$/i);
    if (!match) continue;
    map.set(match[1].toLowerCase(), { name: (match[2] || "Known-bad file").trim(), severity: "critical", category: "known" });
  }
  return map;
}
