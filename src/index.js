/*!
 * JayShield by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JayShield
 */

/**
 * Public programmatic API. Import this to embed JayShield in a build step,
 * a CI job, or a larger security service.
 *
 *   import { scan } from "@jayhackpro/jayshield";
 *   const result = await scan(["./public_html"]);
 */

export { scan, scanBuffer, worstSeverity, SEVERITY_RANK } from "./scanner.js";
export { RULES, rulesForKind, kindForPath } from "./rules.js";
export { runHeuristics, shannonEntropy } from "./heuristics.js";
export { KNOWN_BAD, sha256, matchHash, parseHashList } from "./hashes.js";
export {
  quarantineFiles,
  restoreFiles,
  listQuarantine,
  purgeQuarantine,
  loadManifest,
  QUARANTINE_DIR
} from "./quarantine.js";
export { formatHuman, toJson, summaryLine, banner } from "./report.js";
export { EICAR, writeEicarSample, selfTest } from "./selftest.js";
