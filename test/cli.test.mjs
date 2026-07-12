import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BIN = fileURLToPath(new URL("../bin/jayshield.js", import.meta.url));

function run(args, opts = {}) {
  return spawnSync(process.execPath, [BIN, ...args], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    ...opts
  });
}

test("--version prints a semver and exits 0", () => {
  const r = run(["--version"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test("--help explains usage and exits 0", () => {
  const r = run(["--help"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Usage/);
  assert.match(r.stdout, /--quarantine/);
});

test("an unknown option fails with exit code 2", () => {
  const r = run(["--wat"]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unknown option/);
});

test("scanning a clean folder exits 0", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-cli-clean-"));
  try {
    await fs.writeFile(path.join(dir, "ok.js"), "export const x = 1;");
    const r = run([dir]);
    assert.equal(r.status, 0);
    assert.match(r.stdout, /No malware found/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("scanning an infected file exits 1 and names the rule", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-cli-bad-"));
  try {
    const f = path.join(dir, "x.php");
    await fs.writeFile(f, "<?php eval(base64_decode($_POST['x']));");
    const r = run([f]);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /CRITICAL/);
    assert.match(r.stdout, /Obfuscated eval/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("--json emits valid, structured output", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-cli-json-"));
  try {
    await fs.writeFile(path.join(dir, "x.php"), "<?php system($_GET['c']);");
    const r = run([dir, "--json"]);
    assert.equal(r.status, 1);
    const data = JSON.parse(r.stdout);
    assert.equal(data.tool, "JayShield");
    assert.equal(data.vendor, "JayHackPro");
    assert.equal(data.summary.infected, 1);
    assert.ok(data.infected[0].findings.length >= 1);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("--selftest passes from the command line", () => {
  const r = run(["--selftest"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /All checks passed/);
});

test("a missing target fails cleanly with exit 2", () => {
  const r = run(["/no/such/path/really-not-here"]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /no such file or folder/);
});
