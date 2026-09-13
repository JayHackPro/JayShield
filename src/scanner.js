/*!
 * JayShield by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JayShield
 */

import { promises as fs } from "node:fs";
import { walk, DEFAULT_SKIP_DIRS, skipDirsWithout } from "./walk.js";
import { rulesForKind, globalize, kindForPath } from "./rules.js";
import { runHeuristics, runByteHeuristics, evidenceAt } from "./heuristics.js";
import { matchHash } from "./hashes.js";
import { findWordPressRoots, noteWordPressRoot, classifySiteFile, readWordPressVersion } from "./site.js";

export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const DEFAULT_MAX_BYTES = 5 * 1024 * 1024; // 5 MB
const MATCHES_PER_RULE = 25;
// Files with these kinds are always read as text, even if a stray null byte
// would otherwise mark them binary, so a null cannot be used to hide code.
const SCRIPT_KINDS = new Set(["php", "js", "html", "asp", "python", "perl", "shell"]);

/** Is this buffer most likely binary? Checks for NUL bytes in the head. */
function looksBinary(buffer) {
  const limit = Math.min(buffer.length, 8192);
  for (let i = 0; i < limit; i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

/** All line numbers where a rule pattern hits, capped so a noisy file stays readable. */
function findMatches(text, pattern) {
  const re = globalize(pattern);
  const hits = [];
  let m;
  let guard = 0;
  while ((m = re.exec(text)) !== null && hits.length < MATCHES_PER_RULE) {
    let line = 1;
    for (let i = 0; i < m.index; i++) {
      if (text.charCodeAt(i) === 10) line++;
    }
    hits.push(line);
    if (m.index === re.lastIndex) re.lastIndex++; // avoid a zero-width loop
    if (++guard > 100000) break;
  }
  return hits;
}

/**
 * Scan one already-read file and return its findings.
 *
 * @param {string} filePath
 * @param {Buffer} buffer
 * @param {object} options
 */
export function scanBuffer(filePath, buffer, options = {}) {
  const ignore = options.ignoreRules || new Set();
  const kind = kindForPath(filePath);
  const findings = [];

  // Exact known-bad hash. Always runs, even on binary files.
  const hashHit = matchHash(buffer, options.extraHashes);
  if (hashHit && !ignore.has(hashHit.id)) findings.push(hashHit);

  // Byte and path checks run on every file, so a webshell hidden inside a
  // real (binary) image is still caught.
  for (const h of runByteHeuristics(filePath, buffer)) {
    if (!ignore.has(h.id)) findings.push(h);
  }

  const doText = !looksBinary(buffer) || SCRIPT_KINDS.has(kind);
  if (doText) {
    const text = buffer.toString("utf8");

    for (const rule of rulesForKind(kind, ignore)) {
      const lines = findMatches(text, rule.pattern);
      if (!lines.length) continue;
      findings.push({
        id: rule.id,
        name: rule.name,
        severity: rule.severity,
        category: rule.category,
        line: lines[0],
        matches: lines.length,
        lines,
        evidence: evidenceAt(text, lines[0]),
        description: rule.description,
        references: rule.references || []
      });
    }

    for (const h of runHeuristics({ path: filePath, buffer, text, kind })) {
      if (!ignore.has(h.id)) findings.push(h);
    }
  }

  findings.sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0) || a.line - b.line);
  return findings;
}

/**
 * Scan one or more targets (files or directories).
 *
 * @param {string[]} targets
 * @param {object} [options]
 * @param {number} [options.maxBytes]        skip files larger than this
 * @param {Set<string>} [options.ignoreRules]
 * @param {Map} [options.extraHashes]
 * @param {Set<string>} [options.skipDirs]     directory names to skip (default DEFAULT_SKIP_DIRS)
 * @param {Iterable<string>} [options.includeDirs]  default-skipped names to scan anyway, or "all"
 * @param {boolean} [options.followSymlinks]
 * @param {string} [options.minSeverity]     drop findings below this level
 * @param {(info:{path:string,findings:Array}) => void} [options.onFile]
 * @returns {Promise<object>} the scan result
 */
export async function scan(targets, options = {}) {
  const maxBytes = options.maxBytes || DEFAULT_MAX_BYTES;
  const minRank = SEVERITY_RANK[options.minSeverity] || 0;
  const skipDirs = options.skipDirs || (options.includeDirs ? skipDirsWithout(options.includeDirs) : DEFAULT_SKIP_DIRS);

  const started = Date.now();
  const result = {
    targets,
    infected: [],
    stats: { scanned: 0, skippedLarge: 0, unreadable: 0, bytes: 0, clean: 0, skippedDirs: 0 },
    skippedDirNames: [],
    sites: [],
    countsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
    countsByCategory: {},
    startedAt: new Date(started).toISOString(),
    durationMs: 0
  };

  const skippedNames = new Set();
  const onSkip = (name) => {
    result.stats.skippedDirs++;
    skippedNames.add(name);
  };

  // Which WordPress installs do these targets belong to? Checked up front so
  // a scan of only wp-content still knows its site, and extended during the
  // walk when a wp-settings.php turns up deeper in the tree.
  const wpRoots = new Set(await findWordPressRoots(targets));

  for (const target of targets) {
    for await (const entry of walk(target, { skipDirs, followSymlinks: options.followSymlinks, onSkip })) {
      noteWordPressRoot(entry.path, wpRoots);
      if (entry.size > maxBytes) {
        result.stats.skippedLarge++;
        continue;
      }
      let buffer;
      try {
        buffer = await fs.readFile(entry.path);
      } catch {
        result.stats.unreadable++;
        continue;
      }
      result.stats.scanned++;
      result.stats.bytes += buffer.length;

      let findings = scanBuffer(entry.path, buffer, options);
      if (minRank) findings = findings.filter((f) => (SEVERITY_RANK[f.severity] || 0) >= minRank);

      if (!findings.length) {
        result.stats.clean++;
        continue;
      }
      for (const f of findings) {
        result.countsBySeverity[f.severity] = (result.countsBySeverity[f.severity] || 0) + 1;
        result.countsByCategory[f.category] = (result.countsByCategory[f.category] || 0) + 1;
      }
      const record = { path: entry.path, size: buffer.length, findings };
      result.infected.push(record);
      if (typeof options.onFile === "function") options.onFile(record);
    }
  }

  result.infected.sort(
    (a, b) => topRank(b.findings) - topRank(a.findings) || a.path.localeCompare(b.path)
  );

  // Which flagged files are the site's own code. The report gives these
  // different advice: replace with a clean copy rather than only remove.
  for (const record of result.infected) {
    const site = classifySiteFile(record.path, wpRoots);
    if (site) record.site = site;
  }
  for (const root of [...wpRoots].sort()) {
    result.sites.push({ type: "wordpress", root, version: await readWordPressVersion(root) });
  }

  result.skippedDirNames = [...skippedNames].sort();
  result.durationMs = Date.now() - started;
  return result;
}

function topRank(findings) {
  let top = 0;
  for (const f of findings) top = Math.max(top, SEVERITY_RANK[f.severity] || 0);
  return top;
}

/** The single worst severity in a whole result, or null if clean. */
export function worstSeverity(result) {
  let worst = null;
  let rank = 0;
  for (const level of ["critical", "high", "medium", "low"]) {
    if (result.countsBySeverity[level] > 0 && SEVERITY_RANK[level] > rank) {
      worst = level;
      rank = SEVERITY_RANK[level];
    }
  }
  return worst;
}
