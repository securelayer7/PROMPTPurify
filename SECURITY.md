# Security policy

promptpurify is a security tool. We treat security reports as priority
work.

## Reporting a vulnerability

**Do not open a public GitHub issue for security findings.**

Email **info@securelayer7.net** with:

- A short description of the issue.
- Steps to reproduce (a minimal payload string is usually enough).
- Whether you have already disclosed it elsewhere.

You will get an acknowledgement within **two business days**. Default
disclosure window is **90 days** from acknowledgement, extendable by
mutual agreement.

## In scope

- Bypasses of the structural firewall.
- False-negatives in the model where a plainly malicious prompt
  scores below the production threshold (please file a *class* of
  attack, not a one-off).
- Supply-chain issues — tampered weights, mismatched checksums,
  signature-verification gaps.
- Information leaks from the SDK or output guard.

## Out of scope

- Jailbreaks against the application LLM — vendor issue.
- Content moderation (toxicity, hate, CSAM, self-harm) — different
  problem class.
- Documented limitations in [docs/HONEST-LIMITS.md](docs/HONEST-LIMITS.md).
- Issues requiring a malicious operator.

## Disclosure

- We credit reporters by name (or handle) in release notes unless you
  ask us not to.
- We request a CVE for severity-medium-or-above issues.
- Safe-harbor follows the [disclose.io](https://disclose.io) standard.

## PGP

Request our PGP key by emailing `info@securelayer7.net` with
subject `pgp-key-request`.
