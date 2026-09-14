# Changelog

All notable changes to JayShield are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 1.3.1 - 2026-09-14

A release about being usable on a real site, and honest about what a scan
means.

### Added

- WordPress awareness. A scan recognises a WordPress install and prints its
  version, and every flagged file that belongs to WordPress itself is tagged
  `config`, `core`, `theme`, or `plugin` in the report and in `--json`. Those
  files carry different advice: replace them with a clean copy of the same
  version rather than only removing them, because quarantining one takes the
  site or the theme offline. Scanning only `wp-content` still knows its site.
- `--include <dir,...>` scans folders that are skipped by name, and
  `--include all` scans everything. The report now says how many folders were
  skipped and which names, so a clean result is never quieter than it should
  be. Skipped names are also listed in `--help`.
- A clear answer when given a website address. `jayshield https://example.com`
  used to fail with "no such file or folder"; it now explains that JayShield
  reads files on disk and shows the two ways to scan that site, over SSH or on
  a downloaded copy.
- README: a Requirements section, a step-by-step guide to scanning a WordPress
  site on any hosting, an after-the-scan checklist for the things a file
  scanner cannot do, and a plain list of what JayShield can and cannot promise.
- `scan()` accepts `includeDirs` and returns `sites`, `skippedDirNames`, and
  `stats.skippedDirs`; each infected record may carry `site`. The site helpers
  and the walker are exported from the package.

### Changed

- Folders named `cache` are now scanned. On WordPress, `wp-content/cache` is
  web-served, writable, and a common place to plant a shell, and the upload
  heuristic already treated it as one, so skipping it left a blind spot.
- The upload heuristic no longer flags a cached page whose only PHP is the
  `<?php die(); ?>` guard that WP Super Cache writes. A payload after the
  guard is still caught.
- The clean-scan line now reads "Nothing in the files scanned matched a known
  technique, heuristic, or bad hash", which is what a clean result means.

### Fixed

- A pristine WordPress 7.1 download was reported as 26 infected files, five
  of them critical. Every one was a false positive, and every one is fixed:
  - The WSO webshell rule matched the letters w-s-o inside any word, so
    "Dawson", "WSODs", `useNewSodiumAPI`, and a certificate bundle were all
    called a webshell. It now matches WSO's own function and constant names.
  - The hex-escape rule flagged every long binary constant, in sodium_compat,
    getID3, and SimplePie. It now flags a dangerous function name or request
    variable spelled in hex, or a hex string literal called as a function,
    and is high severity because that is never innocent.
  - The hidden iframe rule matched `marginwidth="0"`, a hidden scratch frame
    with a `javascript:` source, and the Google Tag Manager noscript snippet
    that sits in most theme headers. It now requires a hidden frame with a
    real destination, and a page full of unterminated tags can no longer
    stall a scan.
  - The long-line, high-entropy, and base64-blob heuristics fired on SVG
    icons, entity tables, arrays of class names, and an embedded WebAssembly
    module. Each now also requires a decoder, an execution call, or request
    input on the same file or line, which a packed payload cannot do without.
- Verified clean with the new rules against WordPress 7.1 with and without
  `--include vendor`, WooCommerce 11.1.0, the Astra theme 4.13.11, jQuery
  3.7.1, and Laravel 12.x, while every planted threat in the test fixtures is
  still found.

## 1.3.0 - 2026-09-14

Not on npm. The registry reserved this number during an interrupted publish
and will not release it, so the same code shipped as 1.3.1.

## 1.2.1 - 2026-07-13

### Changed

- The product now carries its registered mark, JayShield®, in the banner
  subtitle and the scan header, matching how the brand appears everywhere else.

## 1.2.0 - 2026-07-13

### Added

- A JayHackPro startup banner. A scan, `--help`, `--selftest`, and the new
  `--banner` now print the JayHackPro block wordmark in green with the JayShield
  subtitle. It is the shared brand mark for JayHackPro tools. Narrow terminals
  get a compact version so it never wraps, and `--no-banner` (or `--json`) turns
  it off for clean and automated output.

## 1.1.0 - 2026-07-13

A precision and coverage pass, verified against real code.

### Added

- Polyglot detection: a webshell hidden inside a real (binary) image, the
  classic upload bypass, is now caught. Byte and path checks run on every
  file, and script files are always read as text, so a stray null byte can no
  longer be used to hide code from the scanner.
- Two high signal rules: a function whose name comes from request input
  (`call_user_func`), and `extract` of request input.

### Changed

- Tightened the reverse shell, webshell banner, and password gate rules so
  they need real malicious code, not a passing mention in a doc comment.
- The upload handler rule is now a low severity advisory, since a plain upload
  form is normal in healthy code.

### Removed

- The backtick execution rule, which matched ordinary markdown backticks in
  documentation and was the main source of noise.

### Fixed

- Verified a clean scan, with zero false positives, across WordPress core,
  jQuery, and the Laravel framework.

## 1.0.0 - 2026-07-13

The first public release.

### Added

- A dependency free malware scanner that walks a folder and flags webshells,
  backdoors, obfuscated payloads, injected iframes and miners, skimmers, spam,
  disguised files, and known bad hashes.
- A signature library of documented malware techniques in `src/rules.js`, plus
  shape and context heuristics for fresh, unseen threats.
- Exact hash detection with an extendable known bad set, seeded with the EICAR
  antivirus test file.
- Safe removal by quarantine: flagged files are moved into a local vault and can
  be restored byte for byte, so nothing is ever lost. Purge is the only
  destructive action and is guarded behind an explicit confirmation.
- A clear ranked report, a `--json` mode and CI friendly exit codes, severity
  filtering, per rule ignores, size limits, and a runtime hash list.
- A built in `--selftest` that proves the whole pipeline end to end using the
  harmless EICAR test file.
- A full test suite on Node's built in test runner, and continuous integration
  on Node 18, 20, and 22.
