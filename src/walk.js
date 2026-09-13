/*!
 * JayShield by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JayShield
 */

import { promises as fs } from "node:fs";
import path from "node:path";

/**
 * Directory names that are noise for a malware scan. They are skipped by
 * default so a scan of a real project stays fast and readable. The scan
 * report says which of them were skipped, and --include puts them back.
 *
 * A plain "cache" folder is NOT on this list on purpose. On a WordPress site
 * wp-content/cache is web-served, often writable, and a common place to plant
 * a shell, so skipping it would turn a real infection into a clean report.
 */
export const DEFAULT_SKIP_DIRS = new Set([
  ".git",
  ".svn",
  ".hg",
  "node_modules",
  "vendor",
  ".jayshield-quarantine",
  ".cache"
]);

/** The skip set minus the names the user asked to include. "all" includes everything. */
export function skipDirsWithout(include) {
  const wanted = new Set(include || []);
  if (wanted.has("all")) return new Set();
  return new Set([...DEFAULT_SKIP_DIRS].filter((name) => !wanted.has(name)));
}

/**
 * Walk a starting path and yield every file underneath it, one at a time,
 * without ever loading the whole tree into memory. Symbolic links are not
 * followed by default, which keeps a scan from escaping the target tree or
 * looping forever.
 *
 * @param {string} root            file or directory to start from
 * @param {object} [options]
 * @param {Set<string>} [options.skipDirs]  directory names to skip
 * @param {boolean} [options.followSymlinks=false]
 * @param {(dir: string) => boolean} [options.enterDir]  return false to skip a directory
 * @param {(name: string, dir: string) => void} [options.onSkip]  called for every directory skipped by name
 */
export async function* walk(root, options = {}) {
  const skipDirs = options.skipDirs || DEFAULT_SKIP_DIRS;
  const followSymlinks = Boolean(options.followSymlinks);
  const enterDir = options.enterDir;
  const onSkip = typeof options.onSkip === "function" ? options.onSkip : null;

  const stat = await fs.lstat(root);
  if (stat.isFile()) {
    yield { path: root, size: stat.size };
    return;
  }
  if (!stat.isDirectory()) return;

  const stack = [root];
  const seen = new Set();

  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      // Unreadable directory (permissions, race). Skip it rather than crash.
      continue;
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      let dirent = entry;

      if (entry.isSymbolicLink()) {
        if (!followSymlinks) continue;
        try {
          const real = await fs.realpath(full);
          if (seen.has(real)) continue;
          seen.add(real);
          dirent = await fs.stat(full);
        } catch {
          continue;
        }
      }

      if (dirent.isDirectory()) {
        if (skipDirs.has(entry.name)) {
          if (onSkip) onSkip(entry.name, full);
          continue;
        }
        if (enterDir && !enterDir(full)) continue;
        stack.push(full);
      } else if (dirent.isFile()) {
        let size = dirent.size;
        if (size === undefined) {
          try {
            size = (await fs.stat(full)).size;
          } catch {
            continue;
          }
        }
        yield { path: full, size };
      }
    }
  }
}
