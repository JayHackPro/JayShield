# Changelog

All notable changes to JayShield are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
