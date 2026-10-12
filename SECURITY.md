# Security Policy

## Status

This project has **not** been independently audited. The DKLs23 core is derived
from Silence Laboratories' audited `silent-shard-dkls23-ll`, but it has been
modified (see `internal/rust/core/MODIFICATIONS.md`), and the ranked
(Birkhoff) signing path, FFI layer and Go bindings are new code
that has not been reviewed by a third party.

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report privately through GitHub's
[private vulnerability reporting](https://github.com/didenkolab/mpc-sdk/security/advisories/new).
Include a description, affected component and version/commit, and a reproduction
if possible. You should get an acknowledgement within 7 days.

## Scope

In scope: key-share leakage, signature forgery, nonce/presignature reuse,
protocol message validation and FFI memory safety.

Out of scope: vulnerabilities in deployments that ignore the cautions in
README.md (for example reusing presignatures or skipping message authentication
between parties).
