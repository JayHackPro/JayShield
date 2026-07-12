import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { scan } from "../src/scanner.js";
import { quarantineFiles, restoreFiles, listQuarantine, purgeQuarantine } from "../src/quarantine.js";

async function infectedTree() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-q-"));
  const shell = path.join(dir, "shell.php");
  await fs.writeFile(shell, "<?php eval(base64_decode($_POST['x'])); // planted");
  return { dir, shell, vault: path.join(dir, ".vault") };
}

async function exists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

test("quarantine removes the file and restore returns it byte for byte", async () => {
  const { dir, shell, vault } = await infectedTree();
  try {
    const original = await fs.readFile(shell);
    const result = await scan([dir]);

    const q = await quarantineFiles(result.infected, { vaultDir: vault });
    assert.equal(q.moved.length, 1);
    assert.equal(await exists(shell), false, "file moved out of the tree");

    const { entries } = await listQuarantine({ vaultDir: vault });
    assert.equal(entries.length, 1);
    assert.equal(entries[0].originalPath, path.resolve(shell));
    assert.ok(entries[0].reason.some((r) => r.severity === "critical"));

    const r = await restoreFiles({ vaultDir: vault });
    assert.equal(r.restored.length, 1);
    assert.equal(await exists(shell), true, "file restored");
    assert.equal(Buffer.compare(original, await fs.readFile(shell)), 0, "identical bytes");

    const after = await listQuarantine({ vaultDir: vault });
    assert.equal(after.entries.length, 0, "vault emptied after restore");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("dry run reports what would move but changes nothing", async () => {
  const { dir, shell, vault } = await infectedTree();
  try {
    const result = await scan([dir]);
    const q = await quarantineFiles(result.infected, { vaultDir: vault, dryRun: true });
    assert.equal(q.moved.length, 1);
    assert.ok(q.moved[0].dryRun);
    assert.equal(await exists(shell), true, "file untouched on a dry run");
    assert.equal(await exists(vault), false, "no vault created on a dry run");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("restore can target a single id and leave the rest", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-q2-"));
  const vault = path.join(dir, ".vault");
  try {
    const a = path.join(dir, "a.php");
    const b = path.join(dir, "b.php");
    await fs.writeFile(a, "<?php eval($_POST['x']);");
    await fs.writeFile(b, "<?php system($_GET['c']);");
    const result = await scan([dir]);
    const q = await quarantineFiles(result.infected, { vaultDir: vault });
    assert.equal(q.moved.length, 2);

    const first = q.moved[0].id;
    const r = await restoreFiles({ vaultDir: vault, ids: [first] });
    assert.equal(r.restored.length, 1);
    const left = await listQuarantine({ vaultDir: vault });
    assert.equal(left.entries.length, 1);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("purge permanently deletes from the vault without restoring", async () => {
  const { dir, shell, vault } = await infectedTree();
  try {
    const result = await scan([dir]);
    await quarantineFiles(result.infected, { vaultDir: vault });
    const p = await purgeQuarantine({ vaultDir: vault });
    assert.equal(p.purged.length, 1);
    assert.equal(await exists(shell), false, "original is not brought back by purge");
    const left = await listQuarantine({ vaultDir: vault });
    assert.equal(left.entries.length, 0);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
