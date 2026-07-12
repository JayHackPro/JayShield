import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));

async function collect() {
  const files = [];
  for (const rel of ["package.json", "README.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md"]) {
    files.push(path.join(root, rel));
  }
  for (const dir of ["src", "bin"]) {
    for (const name of await fs.readdir(path.join(root, dir))) {
      if (name.endsWith(".js")) files.push(path.join(root, dir, name));
    }
  }
  return files;
}

test("no em dashes or en dashes anywhere in shipped source or docs", async () => {
  for (const file of await collect()) {
    const text = await fs.readFile(file, "utf8");
    const match = text.match(/[–—]/);
    assert.equal(match, null, `${path.basename(file)} contains a dash character at index ${match && match.index}`);
  }
});

test("the brand notice rides on every source module", async () => {
  for (const dir of ["src", "bin"]) {
    for (const name of await fs.readdir(path.join(root, dir))) {
      if (!name.endsWith(".js")) continue;
      const text = await fs.readFile(path.join(root, dir, name), "utf8");
      assert.match(text, /JayShield by JayHackPro/, `${name} is missing the brand notice`);
      assert.match(text, /Designed by Jayden Yoon ZK/, `${name} is missing the author line`);
    }
  }
});
