<div align="center">

# JayShield

### Find and remove web malware, webshells, and backdoors.

A fast, dependency free malware scanner and remover for websites and servers.
Point it at a folder, see exactly what is infected, then quarantine the threats
safely. Nothing is ever deleted without your say so.

[![License: MIT](https://img.shields.io/badge/license-MIT-brightgreen)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](package.json)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)
[![CI](https://github.com/JayHackPro/JayShield/actions/workflows/ci.yml/badge.svg)](https://github.com/JayHackPro/JayShield/actions)

**by [JayHackPro](https://www.JayHackPro.com)**

</div>

---

## Why JayShield

When a website is hacked, the attacker usually leaves something behind: a PHP
webshell in the uploads folder, an obfuscated backdoor tacked onto a real file,
an invisible iframe on the homepage, or a cryptocurrency miner buried in a
script. Finding these by hand across thousands of files is slow and easy to get
wrong.

JayShield does it in seconds. It reads every file, matches it against a library
of malware techniques, checks its exact fingerprint against known bad files,
and looks for the tell tale shapes of packed and hidden code. Then it shows you
a clear, ranked report and offers to move the threats into a local vault so your
site stops serving them right away.

It is one small tool with no dependencies, so you can trust it, read it, and run
it anywhere Node is installed.

## Quick start

No install required:

```bash
npx @jayhackpro/jayshield ./public_html
```

Or install it once:

```bash
npm install -g @jayhackpro/jayshield
jayshield ./public_html
```

Prove it works on your machine, using the harmless industry standard test file:

```bash
jayshield --selftest
```

## What it catches

- **Webshells**: c99, r57, WSO, b374k, FilesMan, and the generic remote file
  managers and command runners built on the same patterns.
- **Backdoors**: `eval` of request input, variable functions driven by
  `$_GET` and `$_POST`, the `preg_replace` `/e` trick, remote payloads that are
  fetched and run, hardcoded password gates, and reverse shells.
- **Obfuscation**: decode then run payloads, character code and hex string
  tricks, packed one liners, and large encoded blobs paired with a decoder.
- **Injected front end malware**: hidden or zero size iframes, `document.write`
  of unescaped markup, `eval(atob(...))`, and redirects to decoded URLs.
- **Cryptocurrency miners**: CoinHive and the browser mining scripts that spend
  your visitors' devices.
- **Skimmers and spam**: session cookie exfiltration and blocks of hidden SEO or
  pharma spam links.
- **Disguised files**: PHP hidden inside something that claims to be an image,
  double extensions like `invoice.pdf.php`, and executable scripts sitting in an
  uploads folder where only static files belong.
- **Known bad files**: exact matches against a hash set you can extend, plus the
  EICAR antivirus test file.

## What a scan looks like

```
  ▓▓ JayShield malware scanner by JayHackPro

  Scanned 1,284 files (24.6 MB) in 0.9 s

  CRITICAL public_html/wp-content/uploads/2026/logo.php
     ✕ Obfuscated eval of a decoded payload:1
       Code is hidden inside a decode call and run on the fly, the hallmark of a packed webshell.
       > <?php @eval(base64_decode($_POST["cmd"])); ?>
     ▲ Executable script in an uploads folder:1
       Upload and media folders should hold only static files. An executable script here is very often a planted backdoor.

  HIGH     public_html/index.html
     ▲ Hidden or zero-size iframe:42
       An invisible iframe usually delivers malware or ad fraud to visitors without a trace on the page.

  Summary
  critical 1   high 1   medium 0   low 0
  2 files infected, 1,282 clean

  Review the findings, then remove them safely with:
      jayshield public_html --quarantine
```

## Remove threats safely

JayShield never deletes your files. When you are ready to clean up, quarantine
moves each flagged file into a local vault and records where it came from, so
your live site stops serving it at once while every byte is kept.

```bash
# preview what would move, changing nothing
jayshield ./public_html --quarantine --dry-run

# move every threat into the vault
jayshield ./public_html --quarantine

# see what is in the vault
jayshield --list

# put a file back if a detection was wrong
jayshield --restore <id>

# put everything back
jayshield --restore
```

If you have confirmed the files are malicious and want the disk space back, and
only then, you can permanently delete the vault:

```bash
jayshield --purge --yes
```

## Command reference

```
jayshield [paths...] [options]
```

| Option | What it does |
| --- | --- |
| `--quarantine` | Move every threat into the local vault |
| `--restore [id]` | Put quarantined files back, one or all |
| `--list` | Show what is in the vault |
| `--purge --yes` | Permanently delete the vault (last resort) |
| `--min-severity <level>` | `critical`, `high`, `medium`, or `low` |
| `--ignore-rule <id,...>` | Silence one or more rules by id |
| `--hashes <file>` | Add known bad sha256 hashes, one per line |
| `--max-size <MB>` | Skip files larger than this (default 5) |
| `--vault <dir>` | Quarantine folder (default `.jayshield-quarantine`) |
| `--follow-symlinks` | Follow symbolic links (off by default) |
| `--dry-run` | Show actions without changing anything |
| `--json` | Machine readable output for pipelines |
| `--no-color` | Plain text |
| `-v, --verbose` | Include rule ids and references |
| `--selftest` | Detect the EICAR test file end to end |
| `-V, --version` | Print the version |
| `-h, --help` | Show help |

Exit codes: `0` clean, `1` threats found, `2` error. That makes JayShield easy
to drop into a CI pipeline or a cron job.

## Use it in a pipeline

```bash
# fail the build if anything high or worse is found
jayshield ./release --min-severity high || exit 1

# save a JSON report
jayshield ./public_html --json > jayshield-report.json
```

## Use it from code

```js
import { scan, quarantineFiles } from "@jayhackpro/jayshield";

const result = await scan(["./public_html"]);
console.log(`${result.infected.length} infected of ${result.stats.scanned} scanned`);

if (result.infected.length) {
  await quarantineFiles(result.infected, { vaultDir: ".vault" });
}
```

## Extend it

**Add your own known bad hashes.** Keep a text file with one `sha256` per line,
an optional label after it, and pass it with `--hashes`:

```
# my-threats.txt
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  seen on client site
```

**Silence a noisy rule.** If a rule flags something you know is safe, pass its id:

```bash
jayshield . --ignore-rule js.packer,spam.pharma
```

**Write new rules.** Signatures live in [`src/rules.js`](src/rules.js) as small,
readable objects. Each one has an id, a severity, the file kinds it applies to,
and a pattern. Add one, add a test in [`test/rules.test.mjs`](test/rules.test.mjs),
and send a pull request.

## What it is, and what it is not

JayShield is a fast first responder for web malware. It is excellent at finding
the webshells, backdoors, injections, and known bad files that make up the large
majority of website compromises, and at removing them without data loss.

It is not a full endpoint protection suite and does not run in the kernel or
watch memory in real time. On a busy production server it works best alongside a
host scanner and a web application firewall, as the fast, readable, scriptable
layer you can run on demand and in your pipelines. Signatures find known
techniques, so pair a scan with good backups and prompt updates.

## Development

```bash
npm test        # run the full suite on Node's built in test runner
npm run selftest
```

Zero runtime dependencies, by design. A security tool should be small enough to
read.

## About JayHackPro

JayShield is built and maintained by **JayHackPro® Inc.**, a software
development company focused on cybersecurity, based in Los Angeles, California.

> Let's make the world a better place.

- Website: [JayHackPro.com](https://www.JayHackPro.com)
- X: [@JayHackPro](https://x.com/JayHackPro)
- Contact: info@JayHackPro.com

Designed by Jayden Yoon ZK.

## License

[MIT](LICENSE). Use it freely in your own projects and on your own servers, and
keep the notice. The brand stays behind the code.
