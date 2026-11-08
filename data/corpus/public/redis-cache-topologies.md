# Redis Cache Topologies

Owner: Core Infrastructure

## Supported topologies

- **Standalone** — local development only.
- **Primary/replica** — read-heavy workloads with manual failover.
- **Redis Cluster** — horizontally partitioned production caches.

Production caches run with `maxmemory-policy allkeys-lru` and alert when
eviction rate exceeds 500 keys per second for five minutes.

## Key design

Keys are namespaced as `<service>:<entity>:<id>:<version>`. Large objects
over 100KB should be stored in object storage with Redis holding only a
pointer.

## Failure modes

Cluster failover is automatic but may take up to 20 seconds. Services MUST
treat cache misses as normal and MUST NOT use the cache as the system of
record. Cache stampedes are mitigated with request coalescing and jittered
TTLs.
