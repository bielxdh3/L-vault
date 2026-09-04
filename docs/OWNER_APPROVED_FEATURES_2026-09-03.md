# Owner-approved feature backlog — 2026-09-03

This document records product decisions approved by the repository owner on 2026-09-03.

It is a planning record only. An item appearing here does **not** mean it is implemented, validated, or proven against real recovery hardware. Existing recovery/replica safety gates remain authoritative.

## Approved features

- [#5 — Disaster Recovery Center](https://github.com/bielxdh3/L-vault/issues/5)
- [#6 — Automated Restore Drill](https://github.com/bielxdh3/L-vault/issues/6)
- [#7 — Life Timeline across Gmail, photos and video](https://github.com/bielxdh3/L-vault/issues/7)
- [#8 — Local Semantic Archive](https://github.com/bielxdh3/L-vault/issues/8)
- [#9 — 3-2-1 Backup Score](https://github.com/bielxdh3/L-vault/issues/9)
- [#10 — Immutable backup manifests](https://github.com/bielxdh3/L-vault/issues/10)

## Architectural ordering

1. Immutable backup manifests provide durable evidence that integrity checks, replicas, and restore drills can reference.
2. Automated Restore Drill should prove recovery into an isolated destination and remain distinct from synthetic-only recovery tests.
3. Disaster Recovery Center should aggregate backup freshness, replicas, integrity, restore evidence, and gaps without conflating them.
4. 3-2-1 Backup Score should summarize topology/resilience but remain advisory and explain every deduction.
5. Life Timeline is a derived local view over archived source truth and must preserve timestamp provenance.
6. Local Semantic Archive is a rebuildable local index layer; OCR/transcription/embeddings must not become authoritative backup data.

## Recovery truth

Do not claim a physical clone/boot or complete disaster recovery proof merely because synthetic tests, integrity checks, or planning commands pass. Real recovery evidence must be labeled precisely by what was actually exercised.
