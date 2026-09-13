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
 * Site awareness.
 *
 * JayShield scans files on disk. On a WordPress site some of those files are
 * the site's own code, and the site cannot run without them. When one of them
 * is flagged, the honest advice is different: quarantining wp-config.php or a
 * theme's functions.php takes the site offline, and injected code inside a
 * real file means the whole file is untrusted and should be replaced with a
 * clean copy. This module tells the report which flagged files are which.
 */

// A WordPress root holds these two side by side.
const WP_MARKER_FILE = "wp-settings.php";
const WP_MARKER_DIR = "wp-includes";
const MAX_ANCESTORS = 16;

/** Role labels, in the order the report should mention them. */
export const SITE_ROLES = ["config", "core", "theme", "plugin"];

const ADVICE = {
  config:
    "This is a WordPress configuration file. Quarantining it takes the site offline. Open it, remove the injected code by hand or rebuild it from wp-config-sample.php, and rotate the database password and salts.",
  core:
    "This is a WordPress core file. Quarantining it takes the site offline. Replace it with a clean copy of the same version from wordpress.org, or reinstall core.",
  theme:
    "This is a theme file. Quarantining it breaks the theme and can blank the site. Reinstall the theme from where you got it, or switch to a default theme first.",
  plugin:
    "This is a plugin file. Quarantining it makes WordPress deactivate the plugin. Delete the plugin and reinstall a clean copy from wordpress.org or the vendor."
};

// Root files the site cannot serve without.
const ROOT_CONFIG = new Set(["wp-config.php", ".htaccess", "web.config", ".user.ini", "php.ini"]);
const ROOT_CORE = new Set([
  "index.php", "wp-load.php", "wp-settings.php", "wp-blog-header.php", "wp-cron.php",
  "wp-login.php", "xmlrpc.php", "wp-mail.php", "wp-links-opml.php", "wp-signup.php",
  "wp-activate.php", "wp-comments-post.php", "wp-trackback.php", "wp-config-sample.php"
]);

function toPosix(p) {
  return p.replace(/\\/g, "/");
}

async function isWordPressRoot(dir) {
  try {
    const [f, d] = await Promise.all([
      fs.stat(path.join(dir, WP_MARKER_FILE)),
      fs.stat(path.join(dir, WP_MARKER_DIR))
    ]);
    return f.isFile() && d.isDirectory();
  } catch {
    return false;
  }
}

/** Read the WordPress version from wp-includes/version.php, or null. */
export async function readWordPressVersion(root) {
  try {
    const text = await fs.readFile(path.join(root, WP_MARKER_DIR, "version.php"), "utf8");
    const m = /\$wp_version\s*=\s*['"]([^'"]+)['"]/.exec(text);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

/**
 * Find the WordPress installs that contain or sit under the scan targets.
 * Each target is checked, then its ancestors, so scanning only wp-content
 * still knows which site it belongs to. Roots found while walking are added
 * later by the scanner through noteWordPressRoot().
 *
 * @param {string[]} targets
 * @returns {Promise<string[]>} absolute root directories
 */
export async function findWordPressRoots(targets) {
  const roots = new Set();
  for (const target of targets) {
    let dir;
    try {
      const stat = await fs.stat(target);
      dir = path.resolve(stat.isDirectory() ? target : path.dirname(target));
    } catch {
      continue;
    }
    for (let i = 0; i < MAX_ANCESTORS; i++) {
      if (await isWordPressRoot(dir)) {
        roots.add(dir);
        break;
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  return [...roots];
}

/**
 * Called by the scanner for every file it sees. If this file is the marker
 * of a WordPress install that has not been recorded yet, record its root.
 *
 * @param {string} filePath
 * @param {Set<string>} roots  absolute roots, mutated in place
 */
export function noteWordPressRoot(filePath, roots) {
  if (path.basename(filePath) !== WP_MARKER_FILE) return;
  roots.add(path.resolve(path.dirname(filePath)));
}

/**
 * Which part of a WordPress site a file belongs to, or null for files the
 * site does not need (uploads, cache, stray scripts, anything outside a
 * known install). Only files under a detected root are classified, so a
 * random index.php elsewhere is never called core.
 *
 * @param {string} filePath
 * @param {Iterable<string>} roots  absolute WordPress roots
 * @returns {{type:"wordpress", root:string, role:string, advice:string}|null}
 */
export function classifySiteFile(filePath, roots) {
  const abs = path.resolve(filePath);
  for (const root of roots) {
    const rel = path.relative(root, abs);
    if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) continue;
    const posix = toPosix(rel);
    const role = roleFor(posix);
    if (!role) return null;
    return { type: "wordpress", root, role, advice: ADVICE[role] };
  }
  return null;
}

function roleFor(rel) {
  const parts = rel.split("/");
  const name = parts[parts.length - 1];
  if (parts.length === 1) {
    if (ROOT_CONFIG.has(name)) return "config";
    if (ROOT_CORE.has(name)) return "core";
    return null;
  }
  const top = parts[0];
  if (top === "wp-admin" || top === "wp-includes") return "core";
  if (top === "wp-content" && parts.length >= 3) {
    // wp-content/themes/<theme>/... and wp-content/plugins/<plugin>/...
    // Only code counts; a stray image inside a theme is not site code.
    if (!/\.(?:php\d?|phtml|pht|inc)$/i.test(name)) return null;
    if (parts[1] === "themes" && parts.length >= 4) return "theme";
    if (parts[1] === "plugins" && parts.length >= 4) return "plugin";
  }
  return null;
}

/** Count flagged records by site role, for the report. */
export function countSiteRoles(records) {
  const counts = {};
  for (const r of records) {
    if (!r.site) continue;
    counts[r.site.role] = (counts[r.site.role] || 0) + 1;
  }
  return counts;
}
