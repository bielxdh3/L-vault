# Security Policy

L-Vault handles sensitive local data such as email backups, Google OAuth state, SQLite indexes, media exports, authentication material, and recovery/replication workflows. Security reports should therefore avoid exposing real user data.

## Supported versions

Security fixes target the current `main` branch and the most recent published release when practical.

## Reporting a vulnerability

Do **not** open a public issue for an undisclosed vulnerability.

Preferred reporting path:

1. Use GitHub's private vulnerability reporting / Security Advisory flow for this repository when available.
2. Otherwise contact the repository owner privately through GitHub before disclosing technical details.

Include:

- affected version or commit;
- operating system;
- affected command, service, or workflow;
- minimal reproduction steps using disposable data;
- expected and observed behavior;
- security impact;
- sanitized logs when useful.

Never include live OAuth credentials, tokens, cookies, passwords, SQLite databases, Gmail exports, Takeout archives, personal media, private paths, GPG private keys, backup contents, or clone artifacts containing real user data.

## High-priority areas

Reports are especially useful for:

- authentication, session, CSRF, or password handling;
- OAuth credential or token disclosure;
- path traversal or unsafe archive extraction;
- HTML/content sanitization bypasses;
- unsafe file deletion, restore, replica, or overwrite behavior;
- backup or index integrity issues;
- clone workflow authorization or device-identity failures;
- secrets in logs, reports, or generated files;
- non-loopback exposure that bypasses documented TLS requirements;
- dependency or release-pipeline compromise.

## Safe testing

Use synthetic or disposable vaults only. Do not test destructive behavior against a user's only copy of data or against devices you are not explicitly authorized to modify.

## Disclosure

Please allow reasonable time to investigate and prepare a fix before public disclosure.
