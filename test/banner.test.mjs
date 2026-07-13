import { test } from "node:test";
import assert from "node:assert/strict";
import { renderBanner } from "../src/banner.js";

// Measure what the eye sees, with any ANSI color codes removed.
const ANSI = new RegExp("\\x1b\\[[0-9;]*m", "g");
const strip = (s) => s.replace(ANSI, "");
const visibleRows = (out) => strip(out).split("\n");

test("a wide terminal gets the full block wordmark", () => {
  const out = renderBanner({ subtitle: "JayShield", version: "1.2.0", cols: 100 });
  assert.ok(strip(out).includes("█"), "uses full block characters");
  const art = visibleRows(out).filter((l) => /[█╝═║]/.test(l));
  assert.equal(art.length, 6, "the wordmark is six rows tall");
  assert.ok(art.every((l) => l.length <= 82), "never wider than 82 columns");
});

test("a narrow terminal gets a compact banner that never wraps", () => {
  const rows = visibleRows(renderBanner({ subtitle: "JayShield", cols: 60 }));
  assert.ok(rows.some((l) => l.includes("JayHackPro")), "still names the brand");
  assert.ok(rows.every((l) => l.length <= 60), "fits the width");
});

test("the subtitle, version, and url are shown", () => {
  const out = strip(renderBanner({ subtitle: "JayShield  ·  find and remove web malware", version: "1.2.0", url: "github.com/JayHackPro/JayShield", cols: 100 }));
  assert.match(out, /JayShield/);
  assert.match(out, /find and remove web malware/);
  assert.match(out, /v1\.2\.0/);
  assert.match(out, /github\.com\/JayHackPro\/JayShield/);
});
