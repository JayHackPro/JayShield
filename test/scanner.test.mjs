import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { scan, scanBuffer, worstSeverity } from "../src/scanner.js";

async function tempTree() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-scan-"));
  await fs.mkdir(path.join(dir, "wp-content", "uploads"), { recursive: true });
  await fs.writeFile(path.join(dir, "index.php"), "<?php echo 'ok';");
  await fs.writeFile(path.join(dir, "style.css"), "body{margin:0}");
  await fs.writeFile(path.join(dir, "wp-content", "uploads", "shell.php"), "<?php eval(base64_decode($_POST['x']));");
  await fs.writeFile(path.join(dir, "notes.txt"), "just a note");
  return dir;
}

test("scan walks a tree and reports infected files only", async () => {
  const dir = await tempTree();
  try {
    const result = await scan([dir]);
    assert.equal(result.stats.scanned, 4);
    assert.equal(result.infected.length, 1);
    assert.match(result.infected[0].path, /shell\.php$/);
    assert.ok(result.countsBySeverity.critical >= 1);
    assert.equal(worstSeverity(result), "critical");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("min severity drops lower findings", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-sev-"));
  try {
    // Dean Edwards packer is a low-severity finding on its own.
    await fs.writeFile(path.join(dir, "p.js"), "eval(function(p,a,c,k,e,d){}('',1,1,''.split('|')))");
    const all = await scan([dir]);
    assert.ok(all.infected.length === 1);
    const high = await scan([dir], { minSeverity: "high" });
    assert.equal(high.infected.length, 0);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("ignoreRules silences a specific rule", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-ign-"));
  try {
    await fs.writeFile(path.join(dir, "x.php"), "<?php eval(base64_decode($_POST['x']));");
    const off = await scan([dir], { ignoreRules: new Set(["php.eval_decode", "php.eval_user_input"]) });
    const ids = off.infected.flatMap((r) => r.findings.map((f) => f.id));
    assert.ok(!ids.includes("php.eval_decode"));
    assert.ok(!ids.includes("php.eval_user_input"));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("files above the size cap are skipped, not read", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-big-"));
  try {
    await fs.writeFile(path.join(dir, "huge.php"), "<?php eval(base64_decode($x)); " + "/*".repeat(1000));
    const result = await scan([dir], { maxBytes: 16 });
    assert.equal(result.stats.skippedLarge, 1);
    assert.equal(result.infected.length, 0);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("binary files are not run through the text rules", () => {
  // A NUL byte at the head marks the buffer as binary; text rules are skipped.
  const buf = Buffer.concat([Buffer.from([0]), Buffer.from("eval(base64_decode($_POST['x']))")]);
  const findings = scanBuffer("blob.bin", buf);
  assert.ok(!findings.some((f) => f.id === "php.eval_decode"));
});

test("a clean tree returns an empty result", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-clean-"));
  try {
    await fs.writeFile(path.join(dir, "app.js"), "export const two = 1 + 1;");
    const result = await scan([dir]);
    assert.equal(result.infected.length, 0);
    assert.equal(worstSeverity(result), null);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
