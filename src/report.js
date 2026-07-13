/*!
 * JayShield by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JayShield
 */

import { color, severityColor } from "./colors.js";
import { worstSeverity } from "./scanner.js";

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
  const mark = color.brand(color.bold("JayShield"));
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
  out.push("");

  if (!result.infected.length) {
    out.push("  " + color.green(color.bold("✔ No malware found.")));
    out.push("  " + color.dim("Every file scanned came back clean."));
    out.push("");
    return out.join("\n");
  }

  for (const record of result.infected) {
    const worst = record.findings[0].severity;
    const paint = severityColor(worst);
    const verb = opts.quarantined ? color.dim(" (quarantined)") : "";
    out.push("  " + paint(color.bold(worst.toUpperCase().padEnd(9))) + color.bold(record.path) + verb);

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

  if (!opts.quarantined) {
    out.push("  " + color.dim("Review the findings, then remove them safely with:"));
    out.push("  " + color.brand(`    jayshield ${quoteTargets(result.targets)} --quarantine`));
    out.push("  " + color.dim("Quarantine moves files into a local vault. Put them back any time with --restore."));
    out.push("");
  } else {
    out.push("  " + color.dim("Files above were moved into the quarantine vault. Restore any of them with:"));
    out.push("  " + color.brand("    jayshield --restore"));
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
      summary: {
        scanned: result.stats.scanned,
        clean: result.stats.clean,
        infected: result.infected.length,
        skippedLarge: result.stats.skippedLarge,
        unreadable: result.stats.unreadable,
        worstSeverity: worstSeverity(result),
        bySeverity: result.countsBySeverity,
        byCategory: result.countsByCategory
      },
      infected: result.infected.map((r) => ({
        path: r.path,
        size: r.size,
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
