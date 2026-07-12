/*!
 * JayShield by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JayShield
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { sha256 } from "./hashes.js";

/**
 * Quarantine is how JayShield removes a threat without ever destroying data.
 * A flagged file is moved into a local vault and recorded in a manifest, so
 * the live site stops serving it immediately, yet every byte can be put back
 * with one command if a detection turns out to be wrong. Nothing is deleted
 * unless someone deliberately runs purge.
 */

export const QUARANTINE_DIR = ".jayshield-quarantine";
const MANIFEST = "manifest.json";
const STORE = "files";

function sanitize(name) {
  return String(name).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 80) || "file";
}

async function ensureVault(vaultDir) {
  await fs.mkdir(path.join(vaultDir, STORE), { recursive: true });
}

/** Load the vault manifest, or an empty list if the vault is new. */
export async function loadManifest(vaultDir) {
  try {
    const raw = await fs.readFile(path.join(vaultDir, MANIFEST), "utf8");
    const data = JSON.parse(raw);
    return Array.isArray(data.entries) ? data : { version: 1, entries: [] };
  } catch {
    return { version: 1, entries: [] };
  }
}

async function saveManifest(vaultDir, manifest) {
  const file = path.join(vaultDir, MANIFEST);
  await fs.writeFile(file, JSON.stringify(manifest, null, 2) + "\n", "utf8");
}

/**
 * Move flagged files into the vault.
 *
 * @param {Array<{path:string,findings:Array}>} records  infected records from a scan
 * @param {object} [options]
 * @param {string} [options.vaultDir]
 * @param {boolean} [options.dryRun]   report what would move without touching disk
 * @returns {Promise<{vaultDir:string, moved:Array, failed:Array, dryRun:boolean}>}
 */
export async function quarantineFiles(records, options = {}) {
  const vaultDir = options.vaultDir || QUARANTINE_DIR;
  const dryRun = Boolean(options.dryRun);
  const moved = [];
  const failed = [];

  if (!dryRun) await ensureVault(vaultDir);
  const manifest = dryRun ? { version: 1, entries: [] } : await loadManifest(vaultDir);
  const vaultReal = path.resolve(vaultDir);

  for (const record of records) {
    const abs = path.resolve(record.path);

    // Never quarantine the vault's own files.
    if (abs.startsWith(vaultReal + path.sep)) continue;

    try {
      const stat = await fs.stat(abs);
      const id = sha256(abs).slice(0, 12) + "_" + sanitize(path.basename(abs));
      const storedRel = path.join(STORE, id);

      if (dryRun) {
        moved.push({ path: abs, id, dryRun: true });
        continue;
      }

      const storedAbs = path.join(vaultDir, storedRel);
      await fs.copyFile(abs, storedAbs);
      const digest = sha256(await fs.readFile(storedAbs));
      await fs.chmod(storedAbs, 0o400).catch(() => {});
      await fs.unlink(abs);

      const entry = {
        id,
        originalPath: abs,
        storedPath: storedRel,
        size: stat.size,
        sha256: digest,
        mode: stat.mode & 0o777,
        mtimeMs: stat.mtimeMs,
        quarantinedAt: new Date().toISOString(),
        reason: record.findings.map((f) => ({ id: f.id, name: f.name, severity: f.severity }))
      };
      manifest.entries = manifest.entries.filter((e) => e.originalPath !== abs);
      manifest.entries.push(entry);
      moved.push({ path: abs, id, quarantined: true });
    } catch (err) {
      failed.push({ path: abs, error: err.message });
    }
  }

  if (!dryRun) await saveManifest(vaultDir, manifest);
  return { vaultDir, moved, failed, dryRun };
}

/**
 * Restore quarantined files back to where they came from.
 *
 * @param {object} [options]
 * @param {string} [options.vaultDir]
 * @param {string[]} [options.ids]   restore only these ids, or all if omitted
 * @param {boolean} [options.dryRun]
 */
export async function restoreFiles(options = {}) {
  const vaultDir = options.vaultDir || QUARANTINE_DIR;
  const dryRun = Boolean(options.dryRun);
  const only = options.ids && options.ids.length ? new Set(options.ids) : null;
  const manifest = await loadManifest(vaultDir);

  const restored = [];
  const failed = [];
  const remaining = [];

  for (const entry of manifest.entries) {
    if (only && !only.has(entry.id)) {
      remaining.push(entry);
      continue;
    }
    if (dryRun) {
      restored.push({ path: entry.originalPath, id: entry.id, dryRun: true });
      remaining.push(entry);
      continue;
    }
    try {
      const storedAbs = path.join(vaultDir, entry.storedPath);
      await fs.mkdir(path.dirname(entry.originalPath), { recursive: true });
      await fs.copyFile(storedAbs, entry.originalPath);
      await fs.chmod(entry.originalPath, entry.mode || 0o644).catch(() => {});
      if (entry.mtimeMs) {
        const t = new Date(entry.mtimeMs);
        await fs.utimes(entry.originalPath, t, t).catch(() => {});
      }
      await fs.unlink(storedAbs).catch(() => {});
      restored.push({ path: entry.originalPath, id: entry.id });
    } catch (err) {
      failed.push({ path: entry.originalPath, id: entry.id, error: err.message });
      remaining.push(entry);
    }
  }

  if (!dryRun) {
    manifest.entries = remaining;
    await saveManifest(vaultDir, manifest);
  }
  return { vaultDir, restored, failed };
}

/** List everything currently held in the vault. */
export async function listQuarantine(options = {}) {
  const vaultDir = options.vaultDir || QUARANTINE_DIR;
  const manifest = await loadManifest(vaultDir);
  return { vaultDir, entries: manifest.entries };
}

/**
 * Permanently delete quarantined files. This is the only destructive action
 * in JayShield, so it is never automatic and the CLI guards it behind an
 * explicit confirmation flag.
 */
export async function purgeQuarantine(options = {}) {
  const vaultDir = options.vaultDir || QUARANTINE_DIR;
  const only = options.ids && options.ids.length ? new Set(options.ids) : null;
  const manifest = await loadManifest(vaultDir);
  const purged = [];
  const remaining = [];

  for (const entry of manifest.entries) {
    if (only && !only.has(entry.id)) {
      remaining.push(entry);
      continue;
    }
    await fs.unlink(path.join(vaultDir, entry.storedPath)).catch(() => {});
    purged.push({ path: entry.originalPath, id: entry.id });
  }

  manifest.entries = remaining;
  await saveManifest(vaultDir, manifest);
  return { vaultDir, purged };
}
