# Context Graph Pipeline

Owner: AI Platform

## Purpose

The context graph pipeline ingests documents, extracts entities and
relationships, and materializes a graph used by retrieval and agent memory
services. Ingestion is idempotent and keyed by content hash.

## Stages

1. **Collect** — pull documents from approved sources and record source ACLs.
2. **Extract** — run entity and relation extraction with versioned models.
3. **Resolve** — deduplicate entities and merge provenance pointers.
4. **Materialize** — write nodes and edges to the graph store.
5. **Index** — publish embeddings and lexical indexes for retrieval.

## Authorization invariants

Every derived node MUST retain its source document lineage. Retrieval must
filter candidates by the requesting user's access to the source documents.
Synthesized answers must not surface facts from documents the user cannot
read.

## Ingestion lag

Target freshness is 15 minutes for public sources and 5 minutes for
access-controlled sources. Backfills are throttled to protect the graph store.
