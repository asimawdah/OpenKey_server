# OPAQUE migration plan for OpenKey

## Status

Research and migration design only. This document does not claim that OPAQUE is implemented. The current keyed auth_hash verifier change is an interim database-at-rest mitigation that preserves the existing client API.

## Problem

The current protocol sends a deterministic, reusable client-derived auth_hash to /auth/login. Storing that exact value means a database-only attacker can replay it as a login credential. Replacing it with an ordinary unkeyed digest would stop direct replay of the stored string, but would still give an attacker an offline verifier for password guesses.

## Why OPAQUE

[RFC 9807](https://www.rfc-editor.org/rfc/rfc9807) specifies OPAQUE, an augmented password-authenticated key exchange (aPAKE). It combines an OPRF, client credential recovery, and an authenticated key exchange. During registration, the client sends a registration request, receives a server response, and stores a registration record on the server. During login, the client and server exchange KE1, KE2, and KE3 messages and derive a mutually authenticated session key. The password itself is not disclosed to the server.

OPAQUE also makes server-side credential records unsuitable for direct login replay. It does not make all attacks impossible: online guessing still requires rate limits, and compromise of server-side OPRF secrets and credential records changes the offline-guessing threat. Implementations must follow the RFC's key management, enumeration, constant-time, and input-validation requirements.

RFC 9807 is an IRTF CFRG Informational RFC, not an IETF Standards Track specification. It is a detailed protocol specification, but deployment still requires careful library and implementation review.

## Preserve the vault cryptography

OPAQUE should replace the authentication exchange only. It should not silently replace OpenKey's current master-key derivation, vault-key wrapping, entry encryption, or attachment encryption.

The client can continue using its existing master-password-derived key to unwrap encrypted_vault_key. OPAQUE's session key is used to authenticate the login session; it is not automatically substituted for the vault key. This keeps the authentication migration separate from the vault encryption format.

## Proposed server-side credential record

Store, per account:

- OPAQUE RegistrationRecord and protocol version.
- A stable credential identifier bound to the account identity.
- Server-wide OPRF seed, protected separately from the database.
- Server AKE private key, protected separately from the database (prefer a secret manager or HSM where available).
- A configuration identifier so clients and servers cannot silently downgrade or mix protocol profiles.

Do not store the master password, the old reusable auth_hash, or any client-side OPAQUE ephemeral state as a durable credential. Ephemeral handshake state must be short-lived, scoped to one login attempt, and erased after completion or timeout.

## Client and server rollout

1. **Library spike before production integration.** Evaluate an RFC 9807 implementation against Appendix C test vectors, supported groups, maintenance activity, language bindings, constant-time behavior, zeroization, and security audit scope. Do not implement OPRF, envelope recovery, or 3DH primitives independently.
2. **Choose one interoperable profile.** Follow RFC 9807 Section 7. The RFC's recommended profiles include Ristretto255/SHA-512 with HKDF-SHA-512, HMAC-SHA-512, SHA-512, and Argon2id. Fix the profile and bind it into the protocol context to prevent downgrade and cross-protocol attacks.
3. **Add versioned OPAQUE registration and login endpoints.** Endpoints should transport the RFC-defined messages and delegate all cryptographic operations to the selected library. The server must not accept a client-supplied auth_hash as proof for an OPAQUE account.
4. **Update every client.** Flutter app, browser extension, and CLI must share the same protocol profile and serialization rules. The Flutter app needs a maintained native Rust binding or another independently validated RFC 9807 implementation; browser/Node support alone is not sufficient.
5. **Migrate existing accounts with user participation.** The server cannot convert a legacy auth_hash into an OPAQUE registration record because it does not know the user's master password. After a successful legacy login, an upgraded client can run OPAQUE registration using the password it already has locally. Once an account is marked OPAQUE-enabled, reject legacy auth_hash login for that account. This prevents the old endpoint from remaining a downgrade path.
6. **Retire the legacy protocol.** Track the remaining legacy accounts, provide a clear client-upgrade path, set a deprecation date, and eventually disable /auth/login with auth_hash for all accounts.

## Implementation and deployment safeguards

- Return indistinguishable credential responses for unknown users where required by RFC 9807's client-enumeration mitigation; do not rely only on identical HTTP status codes.
- Keep registration rate-limited; RFC 9807 notes registration still needs application-level enumeration protection.
- Keep online login rate limits and add per-account throttling and abuse monitoring without creating account-lockout denial of service.
- Bind client identity, server identity, credential identifier, and application protocol context as required by the RFC.
- Use the exact RFC serialization and Appendix C test vectors; reject malformed group elements and invalid message lengths.
- Erase ephemeral OPRF/AKE state and sensitive intermediate values as soon as they are no longer needed.
- Test concurrent and multi-worker handshakes. Do not rely on process-local state if the deployment can run multiple API workers or replicas.
- Keep OPRF seed and server AKE private key out of database backups and source control. Plan key backup, rotation, and disaster recovery before enabling OPAQUE accounts.
- Preserve HTTPS, CORS controls, and rate limits. OPAQUE does not remove the need for transport security, particularly during registration.
- Test account recovery, password changes, new-device enrollment, logout, refresh-token revocation, and offline unlock separately from the OPAQUE handshake.

## Candidate implementations to evaluate

- [facebook/opaque-ke](https://github.com/facebook/opaque-ke): Rust implementation based on RFC 9807. Its project documentation reports an NCC Group audit from 2021; the audit scope and version must be checked against the exact release and final RFC before relying on it.
- [@serenity-kit/opaque](https://github.com/serenity-kit/opaque): JavaScript/TypeScript and WebAssembly integration built around opaque-ke; useful to evaluate for the extension and Node-based CLI, but it does not by itself solve the Flutter client integration.
- [bytemare/opaque](https://github.com/bytemare/opaque): Go implementation maintained by an RFC author; its project documentation states it has not been independently audited, so it requires a separate security review before production use.
- [stef/libopaque](https://github.com/stef/libopaque): C implementation with multiple language bindings, but its repository describes an implementation based on an earlier CFRG draft. It must not be assumed to be wire-compatible with RFC 9807 without explicit verification.

The preferred direction to prototype is a shared, well-maintained Rust OPAQUE core with carefully scoped bindings for the Python server, Flutter/Dart, TypeScript extension, and Node CLI. This is a candidate architecture, not a final library selection. The prototype must prove byte-for-byte interoperability across all clients before any account migration.

## Acceptance criteria

- All clients pass RFC 9807 Appendix C vectors for the selected profile.
- Registration and login interoperate across Flutter, extension, CLI, and server.
- Replaying captured KE1/KE2/KE3 messages or a database credential record does not authenticate a new session.
- Server authentication is verified by the client; client authentication is verified by the server before issuing access/refresh tokens.
- Unknown-user responses resist enumeration as specified by the RFC.
- Invalid, replayed, expired, cross-account, and cross-server messages fail closed.
- A database-only compromise does not disclose the password or provide a directly replayable login credential.
- Existing vault ciphertext and wrapped vault keys remain readable without re-encryption.
- Legacy login is disabled for every OPAQUE-enabled account and eventually retired globally.
