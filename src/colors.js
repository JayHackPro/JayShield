/*!
 * JayShield by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JayShield
 */

/**
 * A tiny ANSI color helper with zero dependencies. Color is switched off
 * automatically when the output is not a terminal, when NO_COLOR is set,
 * or when the caller asks for plain text, so piped and CI output stays clean.
 */

function supported() {
  if (process.env.NO_COLOR !== undefined) return false;
  if (process.env.FORCE_COLOR !== undefined) return true;
  return Boolean(process.stdout && process.stdout.isTTY);
}

let enabled = supported();

/** Force color on or off (used by the CLI --no-color flag and by tests). */
export function setColor(on) {
  enabled = Boolean(on);
}

function paint(open, close) {
  return (text) => (enabled ? `[${open}m${text}[${close}m` : String(text));
}

export const color = {
  reset: paint(0, 0),
  bold: paint(1, 22),
  dim: paint(2, 22),
  italic: paint(3, 23),
  underline: paint(4, 24),
  red: paint(31, 39),
  green: paint(32, 39),
  yellow: paint(33, 39),
  blue: paint(34, 39),
  magenta: paint(35, 39),
  cyan: paint(36, 39),
  gray: paint(90, 39),
  brightGreen: paint(92, 39),
  brightRed: paint(91, 39),
  brightYellow: paint(93, 39),
  // JayHackPro brand: a glossy green on black. The wordmark uses the bright
  // green; severity uses the traffic-light set below.
  brand: paint(92, 39)
};

/** Map a finding severity to a consistent color across the whole CLI. */
export function severityColor(severity) {
  switch (severity) {
    case "critical":
      return color.brightRed;
    case "high":
      return color.red;
    case "medium":
      return color.yellow;
    case "low":
      return color.cyan;
    default:
      return color.gray;
  }
}
