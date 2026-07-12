/*!
 * JayShield by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JayShield
 */

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { scan, scanBuffer } from "./scanner.js";
import { quarantineFiles, restoreFiles } from "./quarantine.js";
import { sha256, KNOWN_BAD } from "./hashes.js";

/**
 * The EICAR standard antivirus test string. It is completely harmless by
 * design and exists so anyone can prove a scanner is working without going
 * near real malware. The backslash is written twice so the byte on disk is a
 * single backslash, which is what makes the hash match.
 */
export const EICAR =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/** Write a real EICAR test file into a directory and return its path. */
export async function writeEicarSample(dir, name = "eicar-test.txt") {
  const file = path.join(dir, name);
  await fs.writeFile(file, EICAR, "utf8");
  return file;
}

/**
 * An inert webshell fixture. It contains the exact pattern JayShield detects,
 * but every occurrence sits inside a PHP comment, so the file does nothing at
 * all if it were ever run. It is only used to prove the signature engine
 * fires, and it is written to a temporary folder and deleted right after.
 */
const INERT_SHELL_FIXTURE =
  "<?php\n" +
  "// JayShield self-test fixture. Everything here is inside a comment and does nothing.\n" +
  "// The scanner should flag the pattern on the next line: eval(base64_decode($_POST['x']));\n";

const CLEAN_FIXTURE =
  "<?php\n" +
  "// An ordinary, harmless file used to confirm the scanner does not cry wolf.\n" +
  "function greet($name) { return 'Hello, ' . htmlspecialchars($name); }\n";

/**
 * Run an end-to-end self-test in a temporary folder: detect the EICAR file,
 * confirm its hash, catch an inert webshell pattern, leave a clean file
 * alone, then quarantine and restore. Returns a structured result.
 */
export async function selfTest() {
  const checks = [];
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-selftest-"));

  try {
    const eicarPath = await writeEicarSample(tempDir);
    const shellPath = path.join(tempDir, "inert-shell.php");
    const cleanPath = path.join(tempDir, "clean.php");
    await fs.writeFile(shellPath, INERT_SHELL_FIXTURE, "utf8");
    await fs.writeFile(cleanPath, CLEAN_FIXTURE, "utf8");

    // 1. The EICAR hash is exactly the industry-standard value.
    const eicarDigest = sha256(Buffer.from(EICAR));
    const eicarKnown = KNOWN_BAD.has(eicarDigest);
    checks.push({
      name: "EICAR hash matches the known test-file hash",
      ok: eicarKnown,
      detail: `sha256 ${eicarDigest.slice(0, 16)}...`
    });

    // 2. A full scan finds both threats and skips the clean file.
    const result = await scan([tempDir]);
    const infectedPaths = new Set(result.infected.map((r) => r.path));
    const eicarFound = infectedPaths.has(eicarPath);
    const shellFound = infectedPaths.has(shellPath);
    const cleanFlagged = infectedPaths.has(cleanPath);

    checks.push({ name: "Detects the EICAR test file", ok: eicarFound, detail: eicarPath });
    checks.push({ name: "Detects the inert webshell pattern", ok: shellFound, detail: shellPath });
    checks.push({ name: "Leaves the clean file alone (no false alarm)", ok: !cleanFlagged, detail: cleanPath });

    // 3. Quarantine removes the shell, restore puts it back byte for byte.
    const before = await fs.readFile(shellPath);
    const shellRecord = result.infected.find((r) => r.path === shellPath);
    const q = await quarantineFiles([shellRecord], { vaultDir: path.join(tempDir, ".vault") });
    const goneAfterQuarantine = !(await exists(shellPath));
    checks.push({
      name: "Quarantine moves the threat out of the tree",
      ok: q.moved.length === 1 && goneAfterQuarantine,
      detail: goneAfterQuarantine ? "file removed and vaulted" : "file still present"
    });

    const r = await restoreFiles({ vaultDir: path.join(tempDir, ".vault") });
    const backAgain = await exists(shellPath);
    const identical = backAgain && Buffer.compare(before, await fs.readFile(shellPath)) === 0;
    checks.push({
      name: "Restore returns the file exactly as it was",
      ok: r.restored.length === 1 && identical,
      detail: identical ? "restored byte for byte" : "restore mismatch"
    });

    // 4. A direct buffer scan of the clean fixture is empty.
    const cleanFindings = scanBuffer(cleanPath, Buffer.from(CLEAN_FIXTURE));
    checks.push({
      name: "Clean content scans with zero findings",
      ok: cleanFindings.length === 0,
      detail: `${cleanFindings.length} findings`
    });
  } finally {
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }

  return { passed: checks.every((c) => c.ok), checks };
}

async function exists(p) {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}
