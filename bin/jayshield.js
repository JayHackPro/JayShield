#!/usr/bin/env node
/*!
 * JayShield by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JayShield
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scan } from "../src/scanner.js";
import { parseHashList } from "../src/hashes.js";
import {
  quarantineFiles,
  restoreFiles,
  listQuarantine,
  purgeQuarantine,
  QUARANTINE_DIR
} from "../src/quarantine.js";
import { formatHuman, toJson, summaryLine } from "../src/report.js";
import { renderBanner } from "../src/banner.js";
import { selfTest } from "../src/selftest.js";
import { color, setColor, severityColor } from "../src/colors.js";

const SEVERITIES = ["critical", "high", "medium", "low"];
const here = path.dirname(fileURLToPath(import.meta.url));

/** The JayHackPro brand banner, with the JayShield subtitle. */
function brandBanner(v) {
  return renderBanner({
    subtitle: "JayShield®  ·  find and remove web malware",
    version: v,
    url: "github.com/JayHackPro/JayShield"
  });
}

async function version() {
  try {
    const pkg = JSON.parse(await fs.readFile(path.join(here, "..", "package.json"), "utf8"));
    return pkg.version || "0.0.0";
  } catch {
    return "0.0.0";
  }
}

const BOOLEAN_FLAGS = new Set([
  "quarantine", "restore", "list", "purge", "selftest",
  "json", "follow-symlinks", "no-color", "verbose", "dry-run",
  "yes", "help", "version", "banner", "no-banner"
]);
const VALUE_FLAGS = new Set(["min-severity", "ignore-rule", "hashes", "max-size", "vault"]);
const ALIASES = { h: "help", V: "version", v: "verbose", q: "quarantine", j: "json" };

function parseArgs(argv) {
  const flags = { "ignore-rule": [] };
  const positionals = [];
  let bad = null;

  for (let i = 0; i < argv.length; i++) {
    let arg = argv[i];
    if (arg === "--") {
      positionals.push(...argv.slice(i + 1));
      break;
    }
    if (arg.startsWith("--")) {
      let name = arg.slice(2);
      let value = null;
      const eq = name.indexOf("=");
      if (eq !== -1) {
        value = name.slice(eq + 1);
        name = name.slice(0, eq);
      }
      if (VALUE_FLAGS.has(name)) {
        if (value === null) value = argv[++i];
        if (value === undefined) { bad = `--${name} needs a value`; break; }
        if (name === "ignore-rule") flags["ignore-rule"].push(...value.split(",").map((s) => s.trim()).filter(Boolean));
        else flags[name] = value;
      } else if (BOOLEAN_FLAGS.has(name)) {
        flags[name] = true;
      } else {
        bad = `unknown option --${name}`;
        break;
      }
    } else if (arg.startsWith("-") && arg.length > 1) {
      const short = arg.slice(1);
      const full = ALIASES[short];
      if (!full) { bad = `unknown option -${short}`; break; }
      flags[full] = true;
    } else {
      positionals.push(arg);
    }
  }
  return { flags, positionals, bad };
}

function helpText(v) {
  return `
  ${color.bold("Find and remove web malware, webshells, and backdoors.")}

  ${color.bold("Usage")}
    jayshield [paths...] [options]

  ${color.bold("Scan")}   ${color.dim("(read-only, nothing is changed)")}
    jayshield ./public_html            scan a folder
    jayshield file.php app/            scan several targets
    jayshield .                        scan the current folder
    jayshield . --min-severity high    show only high and critical
    jayshield . --json > report.json   machine-readable output
    jayshield . --verbose              include rule ids and references

  ${color.bold("Remove")}   ${color.dim("(safe: files are moved, never deleted)")}
    jayshield . --quarantine           move every threat into a local vault
    jayshield . --quarantine --dry-run preview what would move
    jayshield --list                   show what is in the vault
    jayshield --restore                put every quarantined file back
    jayshield --restore <id>           put one file back
    jayshield --purge --yes            permanently delete the vault (last resort)

  ${color.bold("Prove it works")}
    jayshield --selftest               detect the EICAR test file end to end

  ${color.bold("Options")}
    --min-severity <level>   critical | high | medium | low
    --ignore-rule <id,...>   silence one or more rules
    --hashes <file>          add known-bad sha256 hashes (one per line)
    --max-size <MB>          skip files larger than this (default 5)
    --vault <dir>            quarantine folder (default ${QUARANTINE_DIR})
    --follow-symlinks        follow symbolic links (off by default)
    --dry-run                show actions without changing anything
    --json                   output JSON
    --no-color               plain text
    --no-banner              hide the startup banner
    --banner                 print the banner and exit
    -v, --verbose            more detail
    -V, --version            print version
    -h, --help               this help

  ${color.bold("Exit codes")}   ${color.dim("0 clean   1 threats found   2 error")}

  ${color.dim("JayHackPro® Inc.  Let's make the world a better place.")}
  ${color.dim("https://github.com/JayHackPro/JayShield")}
`;
}

function fail(message) {
  process.stderr.write(color.red("  error: ") + message + "\n");
  process.stderr.write(color.dim("  run  jayshield --help  for usage\n"));
  process.exitCode = 2;
}

async function main() {
  const { flags, positionals, bad } = parseArgs(process.argv.slice(2));
  if (flags["no-color"] || flags.json) setColor(false);

  const v = await version();
  if (flags.banner) { process.stdout.write(brandBanner(v) + "\n"); return; }
  if (flags.help) { process.stdout.write(brandBanner(v) + helpText(v) + "\n"); return; }
  if (flags.version) { process.stdout.write(v + "\n"); return; }
  if (bad) { fail(bad); return; }

  const vaultDir = flags.vault || QUARANTINE_DIR;

  // ----- Vault management modes
  if (flags.selftest) return runSelfTest(flags, v);
  if (flags.list) return runList(vaultDir, flags);
  if (flags.restore) return runRestore(vaultDir, positionals, flags);
  if (flags.purge) return runPurge(vaultDir, positionals, flags);

  // ----- Scan mode
  if (flags["min-severity"] && !SEVERITIES.includes(flags["min-severity"])) {
    return fail(`--min-severity must be one of ${SEVERITIES.join(", ")}`);
  }

  let extraHashes;
  if (flags.hashes) {
    try {
      extraHashes = parseHashList(await fs.readFile(flags.hashes, "utf8"));
    } catch (err) {
      return fail(`could not read hash list ${flags.hashes}: ${err.message}`);
    }
  }

  let maxBytes;
  if (flags["max-size"]) {
    const mb = Number(flags["max-size"]);
    if (!Number.isFinite(mb) || mb <= 0) return fail("--max-size must be a positive number of megabytes");
    maxBytes = Math.round(mb * 1024 * 1024);
  }

  const targets = positionals.length ? positionals : ["."];
  for (const t of targets) {
    try {
      await fs.access(t);
    } catch {
      return fail(`no such file or folder: ${t}`);
    }
  }

  const result = await scan(targets, {
    ignoreRules: new Set(flags["ignore-rule"]),
    extraHashes,
    maxBytes,
    minSeverity: flags["min-severity"],
    followSymlinks: Boolean(flags["follow-symlinks"])
  });

  const showBanner = !flags.json && !flags["no-banner"];

  let quarantined = false;
  if (flags.quarantine && result.infected.length) {
    const q = await quarantineFiles(result.infected, { vaultDir, dryRun: Boolean(flags["dry-run"]) });
    quarantined = !flags["dry-run"];
    if (flags["dry-run"] && !flags.json) {
      if (showBanner) process.stdout.write(brandBanner(v));
      process.stdout.write(formatHuman(result, { verbose: flags.verbose, header: !showBanner }));
      process.stdout.write("\n  " + color.yellow(color.bold("Dry run")) + color.dim(` would quarantine ${q.moved.length} file(s). Nothing was changed.`) + "\n\n");
      process.exitCode = 1;
      return;
    }
    if (q.failed.length && !flags.json) {
      for (const f of q.failed) process.stderr.write(color.red("  could not quarantine ") + f.path + ": " + f.error + "\n");
    }
  }

  if (flags.json) {
    process.stdout.write(toJson(result, { version: v }) + "\n");
  } else {
    if (showBanner) process.stdout.write(brandBanner(v));
    process.stdout.write(formatHuman(result, { verbose: flags.verbose, quarantined, header: !showBanner }));
    process.stderr.write(color.dim("  " + summaryLine(result)) + "\n");
  }

  process.exitCode = result.infected.length ? 1 : 0;
}

async function runSelfTest(flags, v) {
  const res = await selfTest();
  if (flags.json) {
    process.stdout.write(JSON.stringify(res, null, 2) + "\n");
    process.exitCode = res.passed ? 0 : 1;
    return;
  }
  if (!flags["no-banner"]) process.stdout.write(brandBanner(v));
  process.stdout.write("  " + color.brand(color.bold("self-test")) + "\n\n");
  for (const c of res.checks) {
    const mark = c.ok ? color.green("✔") : color.red("✕");
    process.stdout.write(`  ${mark} ${c.name}\n     ${color.dim(c.detail)}\n`);
  }
  process.stdout.write("\n  " + (res.passed
    ? color.green(color.bold("All checks passed. JayShield is working."))
    : color.red(color.bold("Some checks failed."))) + "\n\n");
  process.exitCode = res.passed ? 0 : 1;
}

async function runList(vaultDir, flags) {
  const { entries } = await listQuarantine({ vaultDir });
  if (flags.json) { process.stdout.write(JSON.stringify(entries, null, 2) + "\n"); return; }
  if (!entries.length) {
    process.stdout.write("\n  " + color.dim("The quarantine vault is empty.") + "\n\n");
    return;
  }
  process.stdout.write("\n  " + color.bold(`Quarantine vault (${entries.length})`) + color.dim(`  ${vaultDir}`) + "\n\n");
  for (const e of entries) {
    const worst = e.reason[0] ? severityColor(e.reason[0].severity)(e.reason[0].severity) : color.dim("unknown");
    process.stdout.write(`  ${color.dim(e.id)}  ${e.originalPath}\n     ${worst}  ${color.dim(e.quarantinedAt)}\n`);
  }
  process.stdout.write("\n  " + color.dim("Restore with  jayshield --restore <id>  or  --restore  for all.") + "\n\n");
}

async function runRestore(vaultDir, ids, flags) {
  const res = await restoreFiles({ vaultDir, ids, dryRun: Boolean(flags["dry-run"]) });
  if (flags.json) { process.stdout.write(JSON.stringify(res, null, 2) + "\n"); return; }
  if (!res.restored.length) {
    process.stdout.write("\n  " + color.dim("Nothing to restore.") + "\n\n");
    return;
  }
  const word = flags["dry-run"] ? "would restore" : "restored";
  process.stdout.write("\n  " + color.green(color.bold(`${word} ${res.restored.length} file(s)`)) + "\n");
  for (const r of res.restored) process.stdout.write("     " + r.path + "\n");
  for (const f of res.failed) process.stderr.write(color.red("     failed: ") + f.path + " " + f.error + "\n");
  process.stdout.write("\n");
}

async function runPurge(vaultDir, ids, flags) {
  if (!flags.yes) {
    return fail("purge permanently deletes quarantined files. Re-run with --yes to confirm.");
  }
  const res = await purgeQuarantine({ vaultDir, ids });
  if (flags.json) { process.stdout.write(JSON.stringify(res, null, 2) + "\n"); return; }
  process.stdout.write("\n  " + color.yellow(color.bold(`purged ${res.purged.length} file(s) permanently`)) + "\n\n");
}

main().catch((err) => {
  process.stderr.write(color.red("  JayShield error: ") + (err && err.stack ? err.stack : String(err)) + "\n");
  process.exitCode = 2;
});
