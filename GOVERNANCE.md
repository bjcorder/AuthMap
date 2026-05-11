# Governance

AuthMap is currently maintained by the repository owner with community input
through issues and pull requests.

## Maintainer responsibilities

Maintainers are responsible for:

- preserving the project's defensive, authorized-use boundary
- reviewing changes to analyzer behavior, reporting language, and security
  posture
- keeping dependency, CI, and release practices suitable for a security tool
- triaging issues and pull requests according to project priorities
- enforcing the code of conduct

## Decision making

For now, decisions are made by maintainer consensus, with the repository owner
as final decision maker when consensus is not possible. Major changes should be
discussed in issues before implementation, especially changes to:

- output schema or compatibility
- supported frameworks and parser strategy
- classification and risk language
- CI, release, or supply-chain security posture
- project scope and non-goals

## Contribution path

Contributors should start with focused issues or pull requests that include
tests or fixtures when analyzer behavior changes. New framework adapters should
follow the adapter contract documented in the implementation architecture.

## Security decisions

Security-sensitive reports, potential vulnerabilities in AuthMap, and
maintainer trust concerns should be handled privately first. Public disclosure
should happen only after sensitive details are removed or a fix is available.
