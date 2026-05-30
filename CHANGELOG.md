# Changelog

[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) +
[SemVer](https://semver.org).

## [0.0.1]

First public release.

- promptpurify model (~14 MB INT8 ONNX, CPU inference, built from
  scratch by SecureLayer7).
- SDK on npm — structural firewall, ONNX runner, browser IIFE.
- Public eval slice + bench script.
- Documentation: README + docs/ (QUICKSTART, HOW-IT-WORKS, BENCHMARKS,
  SAMPLE-DATA, REPRODUCE, HONEST-LIMITS), MODEL_CARD, SECURITY.
- CI + release workflows: cosign keyless signing, SLSA build
  provenance, CycloneDX SBOM, npm publish --provenance, Hugging Face
  mirror.

[0.0.1]: https://github.com/securelayer7/PROMPTPurify/releases/tag/v0.0.1
