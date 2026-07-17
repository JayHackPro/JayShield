import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));

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
