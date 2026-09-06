# Security Policy

Secure-Vibe is a **secure-at-generation** assistant tool: it injects security rules before the AI Agent writes code,
then validates in milliseconds afterwards and loops to repair. It cannot 100% replace manual security review — what it
provides is a high-confidence guardrail; in particular, the regex engine performs **line-level** detection, and complete
taint analysis currently covers only Python.

## Supported Versions

| Version | Support Status |
|------|----------|
| Latest main branch | ✅ Supported |

Historical versions do not receive security fixes; always use the latest version (after installing as a git-managed
checkout, run `cli.py update` for a one-click update).

## Reporting Vulnerabilities / Missed Detection Patterns

### If you find the validator missed an attack pattern (recommended; goes directly into the iteration loop)

```bash
python cli.py missed --pattern "<pattern description or code snippet>" --note "<description>"
```

- Or file an Issue with the `[missed]` prefix in the title.
- Include the trigger scenario (language/framework), an example code snippet, and the rule type expected to match.

### If you find a security vulnerability in the Skill itself

- File an Issue directly, or contact the maintainer privately.
- Please provide: affected version, reproduction steps, and expected vs. actual behavior.

## Sensitive Information Notice

- When reporting a missed detection pattern, **do not paste real keys/passwords/internal URLs**; replace them with
  placeholders (e.g., `sk-****`, `example.com`).
- Secret masking is enabled by default in this project's logs (`config.yaml → logging.mask_secrets`); re-confirm
  desensitization before sharing log excerpts.

## Disclaimer

Secure-Vibe is provided AS-IS (MIT License) and does not constitute a security compliance guarantee. Use it together
with manual review, SAST/DAST, dependency scanning, and other processes.
