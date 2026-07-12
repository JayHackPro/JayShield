import { test } from "node:test";
import assert from "node:assert/strict";
import { selfTest } from "../src/selftest.js";

test("the built-in self-test passes end to end", async () => {
  const res = await selfTest();
  for (const check of res.checks) {
    assert.ok(check.ok, `self-test check failed: ${check.name} (${check.detail})`);
  }
  assert.ok(res.passed);
});
