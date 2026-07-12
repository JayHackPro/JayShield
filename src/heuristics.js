/*!
 * JayShield by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JayShield
 */

import path from "node:path";
import { kindForPath } from "./rules.js";

/**
 * Heuristics look at shape and context rather than a fixed string, so they
 * catch fresh malware that no signature has seen yet. Each returns a finding
 * or null. They are deliberately conservative and mostly medium severity,
 * because unusual code is not always hostile.
 */

/** Shannon entropy in bits per byte. High values mean packed or encrypted data. */
export function shannonEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0;
  const counts = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) counts[buffer[i]]++;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (!counts[i]) continue;
    const p = counts[i] / buffer.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** The longest single line, a quick proxy for a minified or one-line payload. */
export function longestLine(text) {
  let longest = 0;
  let current = 0;
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) {
      if (current > longest) longest = current;
      current = 0;
    } else {
      current++;
    }
  }
  return current > longest ? current : longest;
}

const EXECUTABLE_KINDS = new Set(["php", "asp", "perl"]);
const MEDIA_OR_DOC = new Set([
  ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".svg",
  ".pdf", ".txt", ".csv", ".doc", ".docx", ".xls", ".xlsx", ".zip"
]);
// Web-served upload and media locations, where only static files belong.
// Anchored to real path shapes so a system ancestor like /tmp never counts.
const UPLOAD_PATH = /(?:wp-content\/(?:uploads|cache)|\/uploads?\/|\/media\/|\/attachments?\/|\/userfiles?\/)/i;

/**
 * Run the context and shape heuristics for one file.
 *
 * @param {object} file
 * @param {string} file.path
 * @param {Buffer} file.buffer   raw bytes
 * @param {string} file.text     decoded text (utf8)
 * @param {string} file.kind     from kindForPath
 * @returns {Array<{id:string,name:string,severity:string,category:string,line:number,evidence:string,description:string}>}
 */
export function runHeuristics(file) {
  const findings = [];
  const lower = file.path.toLowerCase();
  const posix = lower.replace(/\\/g, "/");
  const base = path.basename(lower);
  const ext = path.extname(lower);

  // A PHP open tag inside a file that claims to be an image or a document.
  // Real images never contain runnable PHP.
  if (MEDIA_OR_DOC.has(ext) && /<\?php\b|<\?=/.test(file.text)) {
    findings.push(mk(
      "heuristic.php_in_media",
      "PHP code inside a media or document file",
      "critical",
      "webshell",
      file.text,
      /<\?php\b|<\?=/,
      "This file pretends to be an image or document but contains runnable PHP, a common way to smuggle a shell past upload filters."
    ));
  }

  // An executable script sitting in an uploads or media folder, where only
  // static files belong.
  if (EXECUTABLE_KINDS.has(file.kind) && UPLOAD_PATH.test(posix)) {
    findings.push(mk(
      "heuristic.exec_in_uploads",
      "Executable script in an uploads folder",
      "high",
      "webshell",
      file.text,
      /<\?php\b|<\?=|<%|#!/,
      "Upload and media folders should hold only static files. An executable script here is very often a planted backdoor."
    ));
  }

  // A double extension that ends in an executable type, like invoice.pdf.php.
  if (EXECUTABLE_KINDS.has(file.kind) && /\.(?:jpg|jpeg|png|gif|pdf|doc|txt|zip)\.(?:php\d?|phtml|pht|asp|aspx|pl|cgi)$/i.test(base)) {
    findings.push(mk(
      "heuristic.double_extension",
      "Executable file wearing a harmless second extension",
      "high",
      "webshell",
      file.text,
      /.*/,
      "A name like photo.jpg.php is built to look safe while still running as code."
    ));
  }

  // Very high entropy in a text-based source file means the real content is
  // packed or encrypted, which legitimate source rarely is.
  if (file.kind === "php" || file.kind === "asp" || file.kind === "perl") {
    const entropy = shannonEntropy(file.buffer);
    if (entropy >= 5.6 && file.buffer.length >= 512) {
      findings.push(mk(
        "heuristic.high_entropy",
        "Packed or encrypted server script",
        "medium",
        "obfuscation",
        file.text,
        /.*/,
        `Unusually high entropy (${entropy.toFixed(2)} bits per byte) for source code, which points to a packed or encrypted payload.`
      ));
    }
  }

  // A single enormous line in a server script is almost always a minified
  // one-liner payload rather than hand-written code.
  if ((file.kind === "php" || file.kind === "asp") && longestLine(file.text) >= 2000) {
    findings.push(mk(
      "heuristic.long_line",
      "Very long single line in a server script",
      "medium",
      "obfuscation",
      file.text,
      /.{2000,}/,
      "One line thousands of characters long is the shape of a compressed, hidden payload."
    ));
  }

  // A large base64 blob assigned to a variable, then handed straight to a
  // decoder, is the loader half of most packed shells.
  const blob = /['"][A-Za-z0-9+/]{200,}={0,2}['"]/;
  if ((file.kind === "php" || file.kind === "js") && blob.test(file.text) && /(?:base64_decode|atob|gzinflate|gzuncompress)/.test(file.text)) {
    findings.push(mk(
      "heuristic.base64_blob",
      "Large encoded blob with a decoder nearby",
      "medium",
      "obfuscation",
      file.text,
      blob,
      "A big base64 block paired with a decode call is the way most packed payloads are stored on disk."
    ));
  }

  return findings;
}

function mk(id, name, severity, category, text, pattern, description) {
  const line = lineOf(text, pattern);
  return {
    id,
    name,
    severity,
    category,
    line,
    evidence: evidenceAt(text, line),
    description
  };
}

/** Find the 1-based line number of the first match, or 1 if not located. */
function lineOf(text, pattern) {
  const re = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g");
  const m = re.exec(text);
  if (!m) return 1;
  let line = 1;
  for (let i = 0; i < m.index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

/** A short, trimmed snippet of the given line for the report. */
export function evidenceAt(text, line) {
  const lines = text.split("\n");
  const raw = (lines[line - 1] || "").trim();
  return raw.length > 160 ? raw.slice(0, 157) + "..." : raw;
}
