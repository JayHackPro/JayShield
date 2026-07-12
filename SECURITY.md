# Security Policy

JayShield is a security tool, so we hold it to a high bar and welcome reports.

## Reporting a vulnerability

If you find a security issue in JayShield itself, please report it privately
first, before opening a public issue.

- Email: info@JayHackPro.com
- Put "JayShield security" in the subject line.

Please include the version, your platform, and steps to reproduce. We will
confirm we received your report, work on a fix, and credit you when it ships if
you would like that.

## Scope

In scope: bugs in JayShield that could let a crafted file crash the scanner,
escape the scan target, cause a quarantine or restore to write outside the
intended path, or make a scan miss or wrongly report a threat in a way that
harms the user.

Out of scope: the malware samples a user chooses to scan, and a scanner missing
a brand new technique that no signature or heuristic covers yet. Signature
coverage grows over time, and a missed strain is a feature request rather than a
vulnerability. Add a rule and send a pull request.

## Handling malware responsibly

JayShield ships no live malware. Its rules describe techniques, and its tests
build inert fixtures at runtime in a temporary folder and remove them right
after. The only sample it ever writes is the EICAR test string, which is
harmless by design and exists so scanners can be verified safely.
