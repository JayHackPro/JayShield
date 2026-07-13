/*!
 * JayShield by JayHackPro
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JayShield
 */

import { color } from "./colors.js";

/**
 * The JayHackPro startup banner. The block wordmark was generated once with
 * figlet (ANSI Shadow) and embedded here as plain characters, so there is no
 * runtime dependency. It is the brand mark for every JayHackPro tool; each
 * tool passes its own subtitle. Narrow terminals get a compact line instead
 * so the art never wraps.
 */
const ART = [
  "     ██╗ █████╗ ██╗   ██╗██╗  ██╗ █████╗  ██████╗██╗  ██╗██████╗ ██████╗  ██████╗",
  "     ██║██╔══██╗╚██╗ ██╔╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔══██╗██╔═══██╗",
  "     ██║███████║ ╚████╔╝ ███████║███████║██║     █████╔╝ ██████╔╝██████╔╝██║   ██║",
  "██   ██║██╔══██║  ╚██╔╝  ██╔══██║██╔══██║██║     ██╔═██╗ ██╔═══╝ ██╔══██╗██║   ██║",
  "╚█████╔╝██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗██║     ██║  ██║╚██████╔╝",
  " ╚════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝"
];
const ART_WIDTH = 82;
const COMPACT = "\u2593\u2588 JayHackPro \u2588\u2593";

/**
 * Build the banner string.
 * @param {object} [opts]
 * @param {string} [opts.subtitle]  line under the wordmark (the tool and what it does)
 * @param {string} [opts.version]
 * @param {string} [opts.url]
 * @param {number} [opts.cols]      terminal width, defaults to the real one
 */
export function renderBanner(opts = {}) {
  const cols = opts.cols || (process.stdout && process.stdout.columns) || 80;
  const g = color.brightGreen;
  const out = [""];
  if (cols >= ART_WIDTH) {
    for (const row of ART) out.push(g(row));
  } else {
    out.push("  " + g(color.bold(COMPACT)));
  }
  out.push("");
  if (opts.subtitle) {
    out.push("  " + g(color.bold(opts.subtitle)) + (opts.version ? color.dim("   v" + opts.version) : ""));
  }
  if (opts.url) out.push("  " + color.dim(opts.url));
  out.push("");
  return out.join("\n");
}
