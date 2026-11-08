# Redis Cache Specifications

Owner: Core Infrastructure

## Instance sizing

Production clusters are sized for 65% memory utilization at peak. Each shard
targets 25GB of usable memory with replicas in a different availability zone.

## Expiration policy

Session data expires after 30 minutes. Reference data uses a 24-hour TTL with
jittered refresh. No key may be written without an explicit expiration unless
it is backed by a durable store.

## Persistence

Caches do not use AOF. RDB snapshots are retained for incident forensics only
and are never used as a recovery source for customer data.

## Observability

Every service exports hit rate, eviction rate, and command latency. Alerts
fire when p99 latency exceeds 4ms or when the eviction rate doubles within a
ten-minute window.
