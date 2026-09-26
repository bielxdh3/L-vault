# Contributing to L-Vault

Thanks for contributing to L-Vault.

L-Vault is a local-first backup and recovery tool that handles sensitive user data. Contributions should preserve privacy, data integrity, recoverability, and fail-closed behavior.

## Before you start

- Read [README.md](README.md) and [SETUP_WINDOWS.md](SETUP_WINDOWS.md).
- Review [SECURITY.md](SECURITY.md) before security-sensitive work.
- Search existing issues and pull requests.
- Keep each pull request focused on one coherent goal.

## Development setup

Typical setup:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
```

## Validation

Run the relevant checks before opening a pull request:

```powershell
python -m compileall -q src tests
pytest -q
```

If your change affects backup, restore, replication, disk-clone preparation, authentication, Gmail, Takeout ingestion, or file lifecycle, add focused tests using disposable data.

Never claim a validation passed unless it actually completed.

## Security-sensitive areas

Changes need extra scrutiny when they affect:

- OAuth credentials or token storage;
- local authentication, cookies, sessions, or CSRF;
- SQLite state or migrations;
- archive and Takeout extraction;
- Gmail and media ingestion;
- restore, replica, deletion, or overwrite behavior;
- offline clone job construction or device identity;
- TLS, LAN exposure, or local web serving;
- hashing, integrity, or deduplication;
- GPG / artifact verification;
- scheduled tasks or PowerShell automation.

## Pull requests

A good pull request should include:

- the problem and intended behavior;
- files changed;
- exact validations performed;
- tests for behavior changes;
- security/privacy/data-safety implications;
- validations not run and why;
- remaining limitations.

Use the repository pull request template.

## AI-assisted contributions

AI-assisted work is welcome, but contributors remain responsible for the submitted code and claims. Inspect generated diffs and never include private user data, credentials, vault contents, OAuth tokens, backups, or device identifiers.

## License

Unless explicitly stated otherwise, contributions intentionally submitted for inclusion in L-Vault are accepted under the repository's [Apache License 2.0](LICENSE).
