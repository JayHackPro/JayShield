# Contributing to JayShield

Thanks for helping make the web a safer place. Contributions are welcome,
especially new detection rules.

## Getting set up

```bash
git clone https://github.com/JayHackPro/JayShield.git
cd JayShield
npm test
```

There are no dependencies to install. JayShield runs on Node 18 and newer.

## Adding a detection rule

1. Open [`src/rules.js`](src/rules.js) and add a rule object. Give it a stable
   id, an honest severity, the file kinds it applies to, a pattern, a one
   sentence description, and a reference or two.
2. Aim for high signal. A good rule catches a whole technique, not one strain,
   and rarely fires on clean code. When a pattern is common in real software,
   choose a lower severity or require a stronger combination.
3. Add a test in [`test/rules.test.mjs`](test/rules.test.mjs): one case that a
   real payload is caught, and confirm clean code is left alone.
4. Run `npm test` and open a pull request.

## Adding a heuristic

Heuristics look at shape and context rather than a fixed string, and live in
[`src/heuristics.js`](src/heuristics.js). Keep them conservative, since unusual
code is not always hostile, and cover both the positive case and a clean case in
the tests.

## Style

- Zero runtime dependencies. A security tool should be small enough to read.
- Plain, readable JavaScript with clear names.
- Every source file keeps the brand notice at the top.

## Reporting a security issue

Please see [SECURITY.md](SECURITY.md) and report privately first.
