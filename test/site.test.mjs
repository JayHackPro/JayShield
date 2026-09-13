import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  findWordPressRoots,
  classifySiteFile,
  readWordPressVersion,
  countSiteRoles
} from "../src/site.js";

/** A small WordPress install with the markers JayShield looks for. */
async function wordpressTree() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-site-"));
  const site = path.join(dir, "public_html");
  for (const sub of [
    "wp-includes",
    "wp-admin",
    "wp-content/themes/twentytwentyfive",
    "wp-content/plugins/akismet",
    "wp-content/uploads/2026/09",
    "wp-content/cache"
  ]) {
    await fs.mkdir(path.join(site, sub), { recursive: true });
  }
  await fs.writeFile(path.join(site, "wp-settings.php"), "<?php // settings");
  await fs.writeFile(path.join(site, "wp-includes", "version.php"), "<?php\n$wp_version = '6.8.2';\n");
  return { dir, site };
}

test("finds the WordPress root from the root itself, a child folder, and a single file", async () => {
  const { dir, site } = await wordpressTree();
  try {
    assert.deepEqual(await findWordPressRoots([site]), [site]);
    assert.deepEqual(await findWordPressRoots([path.join(site, "wp-content", "uploads")]), [site]);
    assert.deepEqual(await findWordPressRoots([path.join(site, "wp-settings.php")]), [site]);
    // A folder with no WordPress above it finds nothing.
    assert.deepEqual(await findWordPressRoots([dir]), []);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("reads the WordPress version, and returns null when it cannot", async () => {
  const { dir, site } = await wordpressTree();
  try {
    assert.equal(await readWordPressVersion(site), "6.8.2");
    assert.equal(await readWordPressVersion(dir), null);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("classifies the files a WordPress site cannot run without", () => {
  const root = "/srv/site";
  const role = (rel) => {
    const hit = classifySiteFile(path.join(root, rel), [root]);
    return hit ? hit.role : null;
  };
  assert.equal(role("wp-config.php"), "config");
  assert.equal(role(".htaccess"), "config");
  assert.equal(role("index.php"), "core");
  assert.equal(role("wp-load.php"), "core");
  assert.equal(role("wp-includes/load.php"), "core");
  assert.equal(role("wp-admin/includes/file.php"), "core");
  assert.equal(role("wp-content/themes/twentytwentyfive/functions.php"), "theme");
  assert.equal(role("wp-content/plugins/akismet/akismet.php"), "plugin");
  assert.equal(role("wp-content/plugins/akismet/views/config.php"), "plugin");
});

test("does not call the files a site can live without site files", () => {
  const root = "/srv/site";
  const hit = (rel) => classifySiteFile(path.join(root, rel), [root]);
  assert.equal(hit("wp-content/uploads/2026/09/shell.php"), null);
  assert.equal(hit("wp-content/cache/planted.php"), null);
  assert.equal(hit("wp-content/mu-plugins/dropper.php"), null);
  assert.equal(hit("wp-content/themes/twentytwentyfive/screenshot.png"), null);
  assert.equal(hit("wp-content/plugins/akismet/readme.txt"), null);
  assert.equal(hit("wp-content/themes/index.php"), null);
  assert.equal(hit("backup.php"), null);
});

test("a file outside every known root is never called core, whatever its name", () => {
  assert.equal(classifySiteFile("/srv/other/index.php", ["/srv/site"]), null);
  assert.equal(classifySiteFile("/srv/site-two/wp-config.php", ["/srv/site"]), null);
  assert.equal(classifySiteFile("/srv/site/index.php", []), null);
});

test("every classification carries plain advice and the site it belongs to", () => {
  const hit = classifySiteFile("/srv/site/wp-config.php", ["/srv/site"]);
  assert.equal(hit.type, "wordpress");
  assert.equal(hit.root, "/srv/site");
  assert.match(hit.advice, /offline/);
  assert.match(hit.advice, /salts/);
});

test("counts flagged records by role", () => {
  const counts = countSiteRoles([
    { site: { role: "core" } },
    { site: { role: "core" } },
    { site: { role: "theme" } },
    { path: "uploads/shell.php" }
  ]);
  assert.deepEqual(counts, { core: 2, theme: 1 });
});
