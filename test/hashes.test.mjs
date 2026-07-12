import { test } from "node:test";
import assert from "node:assert/strict";
import { sha256, matchHash, parseHashList, KNOWN_BAD } from "../src/hashes.js";
import { EICAR } from "../src/selftest.js";

test("sha256 matches a known reference value", () => {
  assert.equal(
    sha256(Buffer.from("abc")),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  );
});

test("the EICAR test file is in the known-bad set at its real hash", () => {
  const digest = sha256(Buffer.from(EICAR));
  assert.equal(digest, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
  assert.ok(KNOWN_BAD.has(digest));
});

test("matchHash returns a finding for a known-bad buffer and null otherwise", () => {
  const hit = matchHash(Buffer.from(EICAR));
  assert.ok(hit);
  assert.equal(hit.id, "hash.known_bad");
  assert.match(hit.evidence, /^sha256:/);
  assert.equal(matchHash(Buffer.from("totally benign content")), null);
});

test("matchHash honors an extra hash map", () => {
  const buf = Buffer.from("custom bad file");
  const extra = new Map([[sha256(buf), { name: "Custom sample", severity: "high", category: "known" }]]);
  const hit = matchHash(buf, extra);
  assert.ok(hit);
  assert.equal(hit.name, "Custom sample");
  assert.equal(hit.severity, "high");
});

test("parseHashList reads hashes and skips comments and junk", () => {
  const text = [
    "# a comment",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f  eicar",
    "not-a-hash here",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  ].join("\n");
  const map = parseHashList(text);
  assert.equal(map.size, 2);
  assert.equal(map.get("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f").name, "eicar");
});
