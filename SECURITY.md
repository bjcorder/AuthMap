# Security Policy

## Supported versions

AuthMap is pre-1.0 and early-stage. Security fixes are currently made on the
default branch until formal releases begin. Once releases exist, this section
will describe supported release lines.

## Intended use

This project is intended for defensive, authorized application and product-security analysis.

Acceptable use includes:

- Reviewing software you own or are authorized to test
- Improving secure code review coverage
- Building CI guardrails
- Generating evidence for human security review
- Producing defensive documentation and test cases

Unacceptable use includes:

- Exploit automation
- Payload generation for attacking live systems
- Unauthorized scanning
- Credential theft or token abuse
- Instructions for bypassing security controls

## Reporting vulnerabilities

If you discover a security issue in AuthMap itself, please open a private report
through GitHub Security Advisories if enabled, or contact the repository owner
directly.

Do not disclose sensitive customer data, credentials, or exploit details in public issues.

Please include:

- affected version or commit SHA
- impact summary
- reproduction steps using sanitized examples
- whether any reports or artifacts exposed sensitive data

AuthMap data-handling expectations, report sensitivity, CI artifact behavior,
SARIF sharing considerations, baseline handling, and redaction limits are
documented in [docs/DATA_HANDLING.md](docs/DATA_HANDLING.md).

## Safe harbor

Good-faith research into AuthMap itself is welcome when it avoids privacy harm,
service disruption, data destruction, credential exposure, and unauthorized
third-party testing. This safe harbor does not authorize attacks against
projects scanned by AuthMap or systems you do not own or have permission to
test.

## Finding language

This project should report evidence-bound hypotheses unless a finding is mechanically proven. Reports should avoid overstating confidence and should include source evidence and reviewer questions.
