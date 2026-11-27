# Restore selection core

This standalone, dependency-free crate implements only restore option validation, media
selection, ordering, limiting, and the public plan-field projection over caller-supplied
metadata. It does not access files, paths, databases, manifests, or production records,
and it does not perform restore work or runtime integration.

`plan_selection` accepts the existing media types (`all`, `email`, `gmail_attachment`,
`photo`, `video`), conflict policies (`skip`, `rename`, `overwrite`), and an optional
limit from 1 through 1000. An omitted limit selects at most 1000 matching entries.
Selection preserves incoming order. Email selection matches a `media_type` of `email`
or a caller-supplied parsed suffix equal to `.eml` without regard to case. Other media
types require an exact `media_type` match. A candidate's existing `error` status counts
toward the limit and remains in the selected plan.

The conflict policy is validated and carried into the plan; this core does not inspect
filesystem conflicts or derive actions from them.

Callers provide the suffix and a destination display value that is already safe to expose.
The crate accepts no source path. Its returned entries contain only `source_hash`,
`destination`, `action`, `status`, `bytes`, and a non-empty `error` truncated to 240
Unicode characters. `action` and `status` are passed through as supplied.

Run the focused contract tests without network access:

```powershell
cargo test --offline --manifest-path native/restore_selection/Cargo.toml
```
