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

const MEDIA_OR_DOC = new Set([
  ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".svg",
  ".pdf", ".txt", ".csv", ".doc", ".docx", ".xls", ".xlsx", ".zip"
]);
const EXECUTABLE_KINDS = new Set(["php", "asp", "perl"]);
// Web-served upload and media locations, where only static files belong.
// Anchored to real path shapes so a system ancestor like /tmp never counts.
const UPLOAD_PATH = /(?:wp-content\/(?:uploads|cache)|\/uploads?\/|\/media\/|\/attachments?\/|\/userfiles?\/)/i;

const PHP_TAG = Buffer.from("<?php");
const PHP_SHORT = Buffer.from("<?=");

// WP Super Cache and similar plugins store cached pages as .php files that
// open with a `<?php die(); ?>` guard and hold only HTML after it. The guard
// runs nothing, so a file whose only PHP is that guard is not an executable
// planted in the cache. Anything else in the file is still scanned as usual.
const PHP_GUARD = /<\?php\s+(?:die|exit)\s*(?:\(\s*(?:['"][^'"]*['"])?\s*\))?\s*;?\s*\?>/g;
const CODE_MARKER = /<\?php\b|<\?=|<%|#!/;

/** True when the text carries a die/exit guard and no other code marker. */
export function onlyGuardPhp(text) {
  const stripped = text.replace(PHP_GUARD, "");
  return stripped.length !== text.length && !CODE_MARKER.test(stripped);
}

// Shape alone is not evidence. A packed payload has to unpack and run itself,
// so the shape heuristics below also require one of these: a decoder, an
// execution primitive, or request input. An SVG icon on one long line, a
// lookup table full of escapes, or an embedded WebAssembly module has none.
const SERVER_PRIMITIVE = /\b(?:eval|assert|base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|create_function|preg_replace|system|passthru|shell_exec|exec|popen|proc_open)\s*\(|\$_(?:GET|POST|REQUEST|COOKIE)\b|\$\w+\s*\(\s*\$/i;
const BROWSER_SINK = /\beval\s*\(|\bFunction\s*\(|document\.write\s*\(|\.innerHTML\s*=|createElement\s*\(\s*['"]script|location(?:\.href|\.replace)?\s*[=(]|\.src\s*=/;

/** Every line at or over the length cap, so a check can look inside them. */
function longLines(text, min) {
  const out = [];
  let start = 0;
  for (let i = 0; i <= text.length; i++) {
    if (i === text.length || text.charCodeAt(i) === 10) {
      if (i - start >= min) out.push(text.slice(start, i));
      start = i + 1;
    }
  }
  return out;
}

/** Byte offset of the first PHP open tag anywhere in a buffer, or -1. */
function phpTagOffset(buffer) {
  const a = buffer.indexOf(PHP_TAG);
  const b = buffer.indexOf(PHP_SHORT);
  if (a === -1) return b;
  if (b === -1) return a;
  return Math.min(a, b);
}

/**
 * Byte and path heuristics. These run on EVERY file, including ones that look
 * binary, because the classic upload bypass is a real image (binary, full of
 * null bytes) with PHP appended to the end. Skipping binary files would miss
 * exactly that attack.
 */
export function runByteHeuristics(filePath, buffer) {
  const findings = [];
  const lower = filePath.toLowerCase();
  const base = path.basename(lower);
  const ext = path.extname(lower);
  const kind = kindForPath(filePath);

  // A file that claims to be an image or document but carries runnable PHP.
  if (MEDIA_OR_DOC.has(ext)) {
    const at = phpTagOffset(buffer);
    if (at !== -1) {
      findings.push({
        id: "heuristic.php_in_media",
        name: "PHP code inside a media or document file",
        severity: "critical",
        category: "webshell",
        line: 1,
        evidence: `PHP open tag at byte ${at}`,
        description: "This file pretends to be an image or document but contains runnable PHP, a common way to smuggle a shell past upload filters."
      });
    }
  }

  // A double extension that ends in an executable type, like invoice.pdf.php.
  if (EXECUTABLE_KINDS.has(kind) && /\.(?:jpg|jpeg|png|gif|pdf|doc|txt|zip)\.(?:php\d?|phtml|pht|asp|aspx|pl|cgi)$/i.test(base)) {
    findings.push({
      id: "heuristic.double_extension",
      name: "Executable file wearing a harmless second extension",
      severity: "high",
      category: "webshell",
      line: 1,
      evidence: base,
      description: "A name like photo.jpg.php is built to look safe while still running as code."
    });
  }

  return findings;
}

/**
 * Text heuristics for source files. The caller decides which files reach here:
 * text files, and script files even when a stray null byte would otherwise
 * mark them binary, so a null cannot be used to hide code.
 *
 * @param {object} file
 * @param {string} file.path
 * @param {Buffer} file.buffer
 * @param {string} file.text
 * @param {string} file.kind
 */
export function runHeuristics(file) {
  const findings = [];
  const posix = file.path.toLowerCase().replace(/\\/g, "/");

  // An executable script sitting in an uploads or media folder. A cache page
  // whose only PHP is the die() guard is left alone, see onlyGuardPhp.
  if (EXECUTABLE_KINDS.has(file.kind) && UPLOAD_PATH.test(posix) && !onlyGuardPhp(file.text)) {
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

  // Very high entropy in a text-based source file means packed or encrypted
  // content. Legitimate source rarely has it, but data tables do, so the file
  // must also hold something that could unpack or run the payload.
  if (file.kind === "php" || file.kind === "asp" || file.kind === "perl") {
    const entropy = shannonEntropy(file.buffer);
    if (entropy >= 5.6 && file.buffer.length >= 512 && SERVER_PRIMITIVE.test(file.text)) {
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

  // A single enormous line in a server script that also decodes or runs
  // something is the shape of a one-line payload. A long line of SVG markup
  // or a big array literal is just a long line.
  if ((file.kind === "php" || file.kind === "asp") && longestLine(file.text) >= 2000) {
    const payloadLine = longLines(file.text, 2000).find((line) => SERVER_PRIMITIVE.test(line));
    if (payloadLine) {
      findings.push(mk(
        "heuristic.long_line",
        "Very long single line that decodes or runs code",
        "medium",
        "obfuscation",
        file.text,
        /.{2000,}/,
        "One line thousands of characters long, with a decoder or an execution call on it, is the shape of a compressed, hidden payload."
      ));
    }
  }

  // A large base64 blob paired with a decoder is the loader half of most
  // packed shells. In the browser the decoded text must also reach something
  // that runs it; an embedded WebAssembly module or font decoded with atob
  // does not.
  const blob = /['"][A-Za-z0-9+/]{200,}={0,2}['"]/;
  const decoderNearby = file.kind === "js"
    ? /\batob\s*\(/.test(file.text) && BROWSER_SINK.test(file.text)
    : /(?:base64_decode|gzinflate|gzuncompress|gzdecode)\s*\(/.test(file.text);
  if ((file.kind === "php" || file.kind === "js") && blob.test(file.text) && decoderNearby) {
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
