/*!
 * JayShield by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JayShield
 */

import { color, severityColor } from "./colors.js";
import { worstSeverity } from "./scanner.js";
import { countSiteRoles, SITE_ROLES } from "./site.js";

const GLYPH = {
  critical: "✕", // x
  high: "▲", // triangle
  medium: "◆", // diamond
  low: "○" // circle
};

function human(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function seconds(ms) {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

/** The JayShield header line, brand green on the terminal. */
export function banner() {
  const mark = color.brand(color.bold("JayShield®"));
  return `${color.brand("▓▓")} ${mark} ${color.dim("malware scanner by JayHackPro")}`;
}

/** A one-line summary suitable for logs. */
export function summaryLine(result) {
  const worst = worstSeverity(result);
  const files = result.infected.length;
  if (!worst) return `clean: ${result.stats.scanned} files scanned, nothing found`;
  return `${worst} risk: ${files} infected of ${result.stats.scanned} scanned`;
}

/**
 * Format a full human report as a string.
 *
 * @param {object} result   from scan()
 * @param {object} [opts]
 * @param {boolean} [opts.verbose]  include rule ids and references
 * @param {boolean} [opts.quarantined]  findings were just quarantined
 */
export function formatHuman(result, opts = {}) {
  const out = [];
  out.push("");
  if (opts.header !== false) {
    out.push("  " + banner());
    out.push("");
  }
  out.push(
    "  " +
      color.dim(
        `Scanned ${result.stats.scanned} files (${human(result.stats.bytes)}) in ${seconds(result.durationMs)}`
      )
  );

  if (result.stats.skippedLarge || result.stats.unreadable) {
    const notes = [];
    if (result.stats.skippedLarge) notes.push(`${result.stats.skippedLarge} skipped for size`);
    if (result.stats.unreadable) notes.push(`${result.stats.unreadable} unreadable`);
    out.push("  " + color.dim(notes.join(", ")));
  }
  for (const site of result.sites || []) {
    const v = site.version ? `WordPress ${site.version}` : "WordPress (version not read)";
    out.push("  " + color.dim(`${v} at ${site.root}`));
  }
  if (result.stats.skippedDirs) {
    const names = (result.skippedDirNames || []).join(", ");
    const plural = result.stats.skippedDirs === 1 ? "folder" : "folders";
    const include = (result.skippedDirNames || []).join(",") || "all";
    out.push("  " + color.dim(`Skipped ${result.stats.skippedDirs} ${plural} by name (${names}). Scan them too with --include ${include}`));
  }
  out.push("");

  if (!result.infected.length) {
    out.push("  " + color.green(color.bold("✔ No malware found.")));
    out.push("  " + color.dim("Nothing in the files scanned matched a known technique, heuristic, or bad hash."));
    out.push("");
    return out.join("\n");
  }

  for (const record of result.infected) {
    const worst = record.findings[0].severity;
    const paint = severityColor(worst);
    const verb = opts.quarantined ? color.dim(" (quarantined)") : "";
    const site = record.site ? color.dim(` [wordpress ${record.site.role}]`) : "";
    out.push("  " + paint(color.bold(worst.toUpperCase().padEnd(9))) + color.bold(record.path) + site + verb);

    for (const f of record.findings) {
      const g = severityColor(f.severity)(GLYPH[f.severity] || "•");
      const where = f.line ? color.dim(`:${f.line}`) : "";
      const count = f.matches && f.matches > 1 ? color.dim(` (${f.matches} hits)`) : "";
      out.push(`     ${g} ${f.name}${where}${count}`);
      out.push(`       ${color.dim(f.description)}`);
      if (f.evidence) out.push(`       ${color.gray("> " + f.evidence)}`);
      if (opts.verbose) {
        out.push(`       ${color.dim("rule " + f.id)}`);
        for (const ref of f.references || []) out.push(`       ${color.dim("see " + ref)}`);
      }
    }
    out.push("");
  }

  out.push("  " + color.bold("Summary"));
  out.push(
    "  " +
      [
        severityColor("critical")(`critical ${result.countsBySeverity.critical || 0}`),
        severityColor("high")(`high ${result.countsBySeverity.high || 0}`),
        severityColor("medium")(`medium ${result.countsBySeverity.medium || 0}`),
        severityColor("low")(`low ${result.countsBySeverity.low || 0}`)
      ].join("   ")
  );
  out.push(
    "  " +
      color.dim(
        `${result.infected.length} file${result.infected.length === 1 ? "" : "s"} infected, ${result.stats.clean} clean`
      )
  );
  out.push("");

  const roles = countSiteRoles(result.infected);
  const siteFiles = Object.values(roles).reduce((a, b) => a + b, 0);
  if (siteFiles) {
    const breakdown = SITE_ROLES.filter((r) => roles[r]).map((r) => `${roles[r]} ${r}`).join(", ");
    out.push("  " + color.yellow(color.bold(`${siteFiles} flagged file${siteFiles === 1 ? " is" : "s are"} part of WordPress itself`)) + color.dim(` (${breakdown})`));
    out.push("  " + color.dim("Injected code inside a real file means the whole file is untrusted. Replace these with"));
    out.push("  " + color.dim("clean copies of the same version rather than only removing them:"));
    for (const role of SITE_ROLES) {
      if (!roles[role]) continue;
      const advice = result.infected.find((r) => r.site && r.site.role === role).site.advice;
      out.push("  " + color.dim(`  ${role}: `) + color.gray(advice));
    }
    out.push("");
  }

  if (!opts.quarantined) {
    out.push("  " + color.dim("Review the findings, then remove them safely with:"));
    out.push("  " + color.brand(`    jayshield ${quoteTargets(result.targets)} --quarantine`));
    out.push("  " + color.dim("Quarantine moves files into a local vault. Put them back any time with --restore."));
    if (siteFiles) out.push("  " + color.dim("Quarantining the WordPress files above takes the site offline until you replace them."));
    out.push("");
  } else {
    out.push("  " + color.dim("Files above were moved into the quarantine vault. Restore any of them with:"));
    out.push("  " + color.brand("    jayshield --restore"));
    if (siteFiles) {
      out.push("  " + color.yellow("WordPress files were moved too. If the site is offline now, restore them, then replace them with clean copies."));
    }
    out.push("");
  }

  return out.join("\n");
}

function quoteTargets(targets) {
  return targets
    .map((t) => (/\s/.test(t) ? `"${t}"` : t))
    .join(" ");
}

/** A stable, machine-readable object for --json output and CI pipelines. */
export function toJson(result, extra = {}) {
  return JSON.stringify(
    {
      tool: "JayShield",
      vendor: "JayHackPro",
      version: extra.version || null,
      startedAt: result.startedAt,
      durationMs: result.durationMs,
      targets: result.targets,
      sites: result.sites || [],
      summary: {
        scanned: result.stats.scanned,
        clean: result.stats.clean,
        infected: result.infected.length,
        skippedLarge: result.stats.skippedLarge,
        unreadable: result.stats.unreadable,
        skippedDirs: result.stats.skippedDirs || 0,
        skippedDirNames: result.skippedDirNames || [],
        worstSeverity: worstSeverity(result),
        bySeverity: result.countsBySeverity,
        byCategory: result.countsByCategory
      },
      infected: result.infected.map((r) => ({
        path: r.path,
        size: r.size,
        site: r.site ? { type: r.site.type, role: r.site.role, root: r.site.root } : null,
        findings: r.findings.map((f) => ({
          rule: f.id,
          name: f.name,
          severity: f.severity,
          category: f.category,
          line: f.line,
          matches: f.matches || 1,
          evidence: f.evidence,
          description: f.description
        }))
      }))
    },
    null,
    2
  );
}
