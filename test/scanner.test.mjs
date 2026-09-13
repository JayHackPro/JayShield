import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { scan, scanBuffer, worstSeverity } from "../src/scanner.js";

async function tempTree() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-scan-"));
  await fs.mkdir(path.join(dir, "wp-content", "uploads"), { recursive: true });
  await fs.writeFile(path.join(dir, "index.php"), "<?php echo 'ok';");
  await fs.writeFile(path.join(dir, "style.css"), "body{margin:0}");
  await fs.writeFile(path.join(dir, "wp-content", "uploads", "shell.php"), "<?php eval(base64_decode($_POST['x']));");
  await fs.writeFile(path.join(dir, "notes.txt"), "just a note");
  return dir;
}

/** A WordPress install with threats planted where they turn up in real life. */
async function wordpressTree() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-wp-"));
  const mk = async (rel, text) => {
    const full = path.join(dir, rel);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, text);
  };
  await mk("wp-settings.php", "<?php // settings");
  await mk("wp-includes/version.php", "<?php\n$wp_version = '6.8.2';\n");
  await mk("wp-includes/load.php", "<?php // load");
  await mk("wp-config.php", "<?php\ndefine('DB_NAME', 'wp');\neval(base64_decode($_POST['x']));\n");
  await mk("wp-content/themes/twentytwentyfive/functions.php", "<?php\nadd_action('init', 'x');\n$_GET['f']($_GET['a']);\n");
  await mk("wp-content/plugins/akismet/akismet.php", "<?php // clean plugin");
  await mk("wp-content/uploads/2026/09/shell.php", "<?php system($_POST['cmd']);");
  await mk("wp-content/cache/planted.php", "<?php system($_GET['c']);");
  await mk("wp-content/cache/supercache/wp-cache-abc.php", "<?php die(); ?>\n<html><body>cached</body></html>\n");
  await mk("vendor/lib/x.php", "<?php // vendor");
  await mk("node_modules/y/index.js", "module.exports = 1;");
  return dir;
}

test("scan walks a tree and reports infected files only", async () => {
  const dir = await tempTree();
  try {
    const result = await scan([dir]);
    assert.equal(result.stats.scanned, 4);
    assert.equal(result.infected.length, 1);
    assert.match(result.infected[0].path, /shell\.php$/);
    assert.ok(result.countsBySeverity.critical >= 1);
    assert.equal(worstSeverity(result), "critical");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("min severity drops lower findings", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-sev-"));
  try {
    // Dean Edwards packer is a low-severity finding on its own.
    await fs.writeFile(path.join(dir, "p.js"), "eval(function(p,a,c,k,e,d){}('',1,1,''.split('|')))");
    const all = await scan([dir]);
    assert.ok(all.infected.length === 1);
    const high = await scan([dir], { minSeverity: "high" });
    assert.equal(high.infected.length, 0);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("ignoreRules silences a specific rule", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-ign-"));
  try {
    await fs.writeFile(path.join(dir, "x.php"), "<?php eval(base64_decode($_POST['x']));");
    const off = await scan([dir], { ignoreRules: new Set(["php.eval_decode", "php.eval_user_input"]) });
    const ids = off.infected.flatMap((r) => r.findings.map((f) => f.id));
    assert.ok(!ids.includes("php.eval_decode"));
    assert.ok(!ids.includes("php.eval_user_input"));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("files above the size cap are skipped, not read", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-big-"));
  try {
    await fs.writeFile(path.join(dir, "huge.php"), "<?php eval(base64_decode($x)); " + "/*".repeat(1000));
    const result = await scan([dir], { maxBytes: 16 });
    assert.equal(result.stats.skippedLarge, 1);
    assert.equal(result.infected.length, 0);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("binary files are not run through the text rules", () => {
  // A NUL byte at the head marks the buffer as binary; text rules are skipped.
  const buf = Buffer.concat([Buffer.from([0]), Buffer.from("eval(base64_decode($_POST['x']))")]);
  const findings = scanBuffer("blob.bin", buf);
  assert.ok(!findings.some((f) => f.id === "php.eval_decode"));
});

test("a cache folder is scanned by default, and a shell planted there is found", async () => {
  const dir = await wordpressTree();
  try {
    const result = await scan([dir]);
    const paths = result.infected.map((r) => path.relative(dir, r.path).split(path.sep).join("/"));
    assert.ok(paths.includes("wp-content/cache/planted.php"), "planted cache shell was not found");
    // The legacy WP Super Cache page, whose only PHP is the die() guard, is not a threat.
    assert.ok(!paths.includes("wp-content/cache/supercache/wp-cache-abc.php"), "guard-only cache page was flagged");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("skipped folders are counted and named, and --include puts them back", async () => {
  const dir = await wordpressTree();
  try {
    const byDefault = await scan([dir]);
    assert.equal(byDefault.stats.skippedDirs, 2);
    assert.deepEqual(byDefault.skippedDirNames, ["node_modules", "vendor"]);

    const withVendor = await scan([dir], { includeDirs: ["vendor"] });
    assert.equal(withVendor.stats.skippedDirs, 1);
    assert.deepEqual(withVendor.skippedDirNames, ["node_modules"]);
    assert.equal(withVendor.stats.scanned, byDefault.stats.scanned + 1);

    const everything = await scan([dir], { includeDirs: ["all"] });
    assert.equal(everything.stats.skippedDirs, 0);
    assert.equal(everything.stats.scanned, byDefault.stats.scanned + 2);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("a WordPress install is recognised and its own flagged files are marked", async () => {
  const dir = await wordpressTree();
  try {
    const result = await scan([dir]);
    assert.equal(result.sites.length, 1);
    assert.equal(result.sites[0].type, "wordpress");
    assert.equal(result.sites[0].version, "6.8.2");
    assert.equal(result.sites[0].root, path.resolve(dir));

    const roleOf = (name) => {
      const r = result.infected.find((x) => x.path.endsWith(name));
      assert.ok(r, `${name} was not flagged`);
      return r.site ? r.site.role : null;
    };
    assert.equal(roleOf("wp-config.php"), "config");
    assert.equal(roleOf("functions.php"), "theme");
    assert.equal(roleOf("shell.php"), null);
    assert.equal(roleOf("planted.php"), null);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("scanning only wp-content still knows which WordPress site it belongs to", async () => {
  const dir = await wordpressTree();
  try {
    const result = await scan([path.join(dir, "wp-content")]);
    assert.equal(result.sites.length, 1);
    assert.equal(result.sites[0].root, path.resolve(dir));
    const theme = result.infected.find((x) => x.path.endsWith("functions.php"));
    assert.equal(theme.site.role, "theme");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("a plain folder reports no site and no site roles", async () => {
  const dir = await tempTree();
  try {
    const result = await scan([dir]);
    assert.deepEqual(result.sites, []);
    assert.ok(result.infected.every((r) => !r.site));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("a clean tree returns an empty result", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jayshield-clean-"));
  try {
    await fs.writeFile(path.join(dir, "app.js"), "export const two = 1 + 1;");
    const result = await scan([dir]);
    assert.equal(result.infected.length, 0);
    assert.equal(worstSeverity(result), null);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
