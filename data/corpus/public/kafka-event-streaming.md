# Kafka Event Streaming Architecture

Owner: Data Platform

## Cluster topology

We run three Kafka clusters: `events-prod`, `events-staging`, and
`analytics-prod`. Each cluster has a minimum of three brokers spread across
availability zones with a replication factor of three and
`min.insync.replicas=2`.

## Topic conventions

Topic names follow `<domain>.<entity>.<event-version>`, for example
`billing.invoice.created-v1`. Producers MUST set a deterministic partition
key so that per-entity ordering is preserved.

## Schema management

All topics are registered in the schema registry using Avro. Schema changes
must be backward compatible. Breaking changes require a new topic version.

## Consumer groups

Consumers use idempotent processing and commit offsets only after successful
downstream writes. Dead-letter topics are suffixed with `.dlq` and are
monitored by the data platform on-call rotation.
