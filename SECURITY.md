# Security Policy

## Supported Versions

Security fixes are applied to the latest released major/minor version.

| Version | Supported |
|---------|-----------|
| 2.x     | ✅        |
| < 2.0   | ❌        |

## Reporting a Vulnerability

Please report suspected vulnerabilities privately via
[GitHub Security Advisories](https://github.com/gourdian25/gourdiantoken/security/advisories/new)
rather than opening a public issue.

Include:

- A description of the issue and its impact
- Steps or a proof-of-concept to reproduce
- Affected version(s)

You can expect an acknowledgment within a week. Once a fix is available, the
advisory will be published together with a patched release.

## Scope Notes

gourdiantoken issues, verifies, revokes, and rotates JWTs; it does not manage
transport security, secret distribution, or the trust boundary around wherever
its revocation/rotation state is stored. The most relevant security
considerations for users are:

- **Key management is the caller's responsibility**: gourdiantoken loads
  signing keys (HMAC secrets or PEM asymmetric keys) that the caller provides
  and never generates, stores, or rotates them itself. Key rotation, secret
  storage, and file permissions on private key material are the integrating
  application's responsibility (though `checkFilePermissions` will refuse to
  load a private key file with overly permissive mode bits).
- **Revocation/rotation state trust**: the `TokenRepository` backends (Redis,
  Mongo, Postgres, in-memory) are trusted stores — gourdiantoken assumes whatever
  backend it's pointed at is not tamperable by an attacker. If that store is
  compromised, an attacker can un-revoke or replay tokens; securing the
  backend (network isolation, auth, TLS) is the deployer's job, not this
  library's.
- **Algorithm confusion**: `SigningMethod` must match `Algorithm` and this is
  validated at construction time (`validateAlgorithmAndMethod`), but callers
  parsing tokens from elsewhere with their own `jwt` usage should still pin
  expected algorithms rather than trust the token's `alg` header alone.
- **Claim validation is exp/mle only by default**: gourdiantoken validates
  expiry (`exp`) and max-lifetime (`mle`) claims, but does not validate
  audience, issuer, or other custom claims unless the caller checks them —
  those checks remain the integrating application's responsibility.
