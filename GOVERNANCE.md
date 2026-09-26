# Governance

L-Vault currently uses a maintainer-led governance model.

## Maintainer

The repository owner, `@bielxdh3`, is the final decision maker for project scope, roadmap, merges, releases, security response, compatibility, and repository policy.

## Decision model

- Issues define reproducible problems and scoped proposals.
- Pull requests implement one coherent goal and provide validation evidence.
- `main` is the integrated source of truth.
- Privacy, data integrity, recoverability, and fail-closed behavior take precedence over convenience.

## Security-sensitive decisions

Changes affecting OAuth, local authentication, backup/restore, replication, destructive file operations, archive ingestion, disk-clone preparation, cryptographic verification, TLS/LAN exposure, or scheduled automation require explicit review.

## Releases

A merged change is not automatically a production-readiness claim. Release notes should state known limitations and any unvalidated recovery or hardware paths.

## Contributions

Contributions are welcome, but a technically valid change may still be declined when it conflicts with project scope, data-safety requirements, or maintainability.

## Governance changes

This file may evolve as sustained contribution volume or additional maintainers make a broader model useful.
