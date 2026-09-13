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

test("a website address is refused with an explanation, not a confusing file error", () => {
  for (const target of ["https://example.com", "http://example.com/wp-admin/", "example.com", "www.example.com/blog"]) {
    const r = run([target]);
    assert.equal(r.status, 2, target);
    assert.match(r.stderr, /scans files on disk/, target);
    assert.match(r.stderr, /cannot connect to/, target);
    assert.match(r.stderr, /over SSH/, target);
    assert.match(r.stderr, /downloaded copy/, target);
    assert.doesNotMatch(r.stderr, /no such file or folder/, target);
  }
});

test("--include scans a folder that is skipped by name", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-cli-include-"));
  try {
    await fs.mkdir(path.join(dir, "vendor"));
    await fs.writeFile(path.join(dir, "ok.php"), "<?php echo 1;");
    await fs.writeFile(path.join(dir, "vendor", "bad.php"), "<?php eval(base64_decode($_POST['x']));");

    const skipped = run([dir, "--json"]);
    assert.equal(skipped.status, 0);
    const a = JSON.parse(skipped.stdout);
    assert.equal(a.summary.skippedDirs, 1);
    assert.deepEqual(a.summary.skippedDirNames, ["vendor"]);

    const included = run([dir, "--json", "--include", "vendor"]);
    assert.equal(included.status, 1);
    const b = JSON.parse(included.stdout);
    assert.equal(b.summary.skippedDirs, 0);
    assert.equal(b.summary.infected, 1);

    const human = run([dir]);
    assert.match(human.stdout, /Skipped 1 folder by name \(vendor\)/);
    assert.match(human.stdout, /--include vendor/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("the report names WordPress files and says to replace them, in text and in JSON", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-cli-wp-"));
  try {
    await fs.mkdir(path.join(dir, "wp-includes"));
    await fs.writeFile(path.join(dir, "wp-settings.php"), "<?php // settings");
    await fs.writeFile(path.join(dir, "wp-includes", "version.php"), "<?php $wp_version = '6.8.2';");
    await fs.writeFile(path.join(dir, "wp-config.php"), "<?php eval(base64_decode($_POST['x']));");

    const human = run([dir]);
    assert.equal(human.status, 1);
    assert.match(human.stdout, /WordPress 6\.8\.2 at /);
    assert.match(human.stdout, /\[wordpress config\]/);
    assert.match(human.stdout, /part of WordPress itself/);
    assert.match(human.stdout, /takes the site offline/);

    const json = JSON.parse(run([dir, "--json"]).stdout);
    assert.equal(json.sites[0].version, "6.8.2");
    assert.equal(json.infected[0].site.role, "config");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
