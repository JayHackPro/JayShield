import { test } from "node:test";
import assert from "node:assert/strict";
import { scanBuffer } from "../src/scanner.js";
import { shannonEntropy, longestLine } from "../src/heuristics.js";

const idsFor = (p, content) => scanBuffer(p, Buffer.from(content)).map((f) => f.id);

test("shannonEntropy is low for repetition and high for randomness", () => {
  assert.ok(shannonEntropy(Buffer.from("aaaaaaaaaa")) < 0.5);
  const random = Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 131 + 7) % 256));
  assert.ok(shannonEntropy(random) > 7);
});

test("longestLine finds the longest run between newlines", () => {
  assert.equal(longestLine("ab\ncdef\ng"), 4);
});

test("flags PHP hidden inside a file that claims to be an image", () => {
  assert.ok(idsFor("avatar.jpg", "GIF89a<?php system($_GET['c']); ?>").includes("heuristic.php_in_media"));
});

test("flags an executable wearing a harmless second extension", () => {
  assert.ok(idsFor("invoice.pdf.php", "<?php // planted").includes("heuristic.double_extension"));
});

test("flags an executable script inside a web uploads folder", () => {
  const ids = idsFor("/var/www/site/wp-content/uploads/2026/x.php", "<?php echo 1;");
  assert.ok(ids.includes("heuristic.exec_in_uploads"));
});

test("does NOT flag a normal script just because a system ancestor is named tmp or cache", () => {
  // Regression: earlier the heuristic walked every ancestor up to root, so a
  // file under /private/tmp or /var/cache was wrongly called an upload.
  assert.deepEqual(idsFor("/private/tmp/project/includes/theme.php", "<?php echo 'hi';"), []);
  assert.deepEqual(idsFor("/var/cache/app/lib/util.php", "<?php return 1;"), []);
});

test("flags packed or one-line payloads by shape", () => {
  const packed = "<?php $x='" + "A".repeat(2600) + "'; // one very long line";
  assert.ok(idsFor("packed.php", packed).includes("heuristic.long_line"));

  const blob = "<?php $data = '" + "QUJD".repeat(80) + "'; echo base64_decode($data);";
  assert.ok(idsFor("loader.php", blob).includes("heuristic.base64_blob"));
});
