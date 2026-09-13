import { test } from "node:test";
import assert from "node:assert/strict";
import { scanBuffer } from "../src/scanner.js";
import { shannonEntropy, longestLine, onlyGuardPhp } from "../src/heuristics.js";

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

test("catches PHP hidden in a REAL binary image, the classic upload bypass", () => {
  // A PNG header carries null bytes, so this file looks binary. Skipping it
  // would miss exactly this polyglot. The webshell is appended at the end.
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d]),
    Buffer.from('<?php system($_GET["c"]); ?>')
  ]);
  assert.ok(scanBuffer("avatar.png", png).map((f) => f.id).includes("heuristic.php_in_media"));
});

test("a null byte cannot hide code inside a script file", () => {
  const buf = Buffer.concat([Buffer.from([0]), Buffer.from("<?php eval(base64_decode($_POST['x']));")]);
  assert.ok(scanBuffer("x.php", buf).map((f) => f.id).includes("php.eval_decode"));
});

test("flags an executable wearing a harmless second extension", () => {
  assert.ok(idsFor("invoice.pdf.php", "<?php // planted").includes("heuristic.double_extension"));
});

test("flags an executable script inside a web uploads folder", () => {
  const ids = idsFor("/var/www/site/wp-content/uploads/2026/x.php", "<?php echo 1;");
  assert.ok(ids.includes("heuristic.exec_in_uploads"));
});

test("a cached page whose only PHP is the die() guard is not an executable in the cache", () => {
  const guard = "<?php die(); ?>\n<!DOCTYPE html><html><body>cached</body></html>\n";
  assert.equal(onlyGuardPhp(guard), true);
  assert.equal(onlyGuardPhp("<?php exit; ?>\n<html></html>"), true);
  assert.equal(onlyGuardPhp("<html>no php at all</html>"), false);
  assert.equal(onlyGuardPhp("<?php die(); ?>\n<?php system($_GET['c']); ?>"), false);
  assert.deepEqual(idsFor("/var/www/site/wp-content/cache/supercache/wp-cache-1.php", guard), []);
  // The guard does not hide a payload that follows it.
  const ids = idsFor("/var/www/site/wp-content/cache/supercache/wp-cache-2.php", "<?php die(); ?>\n<?php system($_GET['c']); ?>");
  assert.ok(ids.includes("heuristic.exec_in_uploads"));
  assert.ok(ids.includes("php.exec_user_input"));
});

test("does NOT flag a normal script just because a system ancestor is named tmp or cache", () => {
  // Regression: earlier the heuristic walked every ancestor up to root, so a
  // file under /private/tmp or /var/cache was wrongly called an upload.
  assert.deepEqual(idsFor("/private/tmp/project/includes/theme.php", "<?php echo 'hi';"), []);
  assert.deepEqual(idsFor("/var/cache/app/lib/util.php", "<?php return 1;"), []);
});

test("flags packed or one-line payloads by shape", () => {
  const packed = "<?php eval(gzinflate(base64_decode('" + "A".repeat(2600) + "')));";
  assert.ok(idsFor("packed.php", packed).includes("heuristic.long_line"));

  const blob = "<?php $data = '" + "QUJD".repeat(80) + "'; echo base64_decode($data);";
  assert.ok(idsFor("loader.php", blob).includes("heuristic.base64_blob"));

  const browser = "var p='" + "QUJD".repeat(80) + "'; document.write(atob(p));";
  assert.ok(idsFor("loader.js", browser).includes("heuristic.base64_blob"));
});

test("shape alone is not a finding: long data lines, hex tables, and embedded wasm are left alone", () => {
  // Real WordPress core shapes that used to be flagged.
  const svgLine = "<?php return array( 'icon' => '<svg " + "d=\"M0 0h24v24H0z\" ".repeat(150) + "' );";
  assert.deepEqual(idsFor("wp-includes/blocks/social-link.php", svgLine), []);

  const entityTable = "<?php\n" + "$t = array(\n" + Array.from({ length: 400 }, (_, i) => `  '&#x${(0x1f300 + i).toString(16)};&#x200d;&#xfe0f;' => ${i},`).join("\n") + "\n);";
  assert.deepEqual(idsFor("wp-includes/formatting.php", entityTable), []);

  const wasm = "const bytes = atob('" + "AGFzbQEAAAAB".repeat(40) + "'); WebAssembly.instantiate(Uint8Array.from(bytes, c => c.charCodeAt(0)));";
  assert.deepEqual(idsFor("router/index.js", wasm), []);

  // High entropy with no way to unpack or run anything is data, not a payload.
  const noise = "<?php\n$table = \"" + Array.from({ length: 4000 }, (_, i) => "\\x" + ((i * 7919) % 256).toString(16).padStart(2, "0")).join("") + "\";";
  assert.ok(!idsFor("table.php", noise).includes("heuristic.high_entropy"));
  assert.ok(!idsFor("table.php", noise).includes("php.hex_obfuscation"));

  // A dense payload with a decoder next to it is still flagged. The bytes are
  // pseudo-random so the base64 text is close to the entropy of a real packer.
  let seed = 12345;
  const bytes = Buffer.alloc(6000);
  for (let i = 0; i < bytes.length; i++) {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    bytes[i] = (seed >>> 16) & 0xff;
  }
  const packed = "<?php eval(gzinflate(base64_decode('" + bytes.toString("base64") + "')));";
  assert.ok(idsFor("packed.php", packed).includes("heuristic.high_entropy"));
  // The same dense blob with nothing to unpack it is left alone.
  const data = "<?php $blob = '" + bytes.toString("base64") + "';";
  assert.ok(!idsFor("data.php", data).includes("heuristic.high_entropy"));
});
