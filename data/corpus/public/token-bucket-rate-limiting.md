# Token Bucket Rate Limiting

Owner: Edge Platform

## Algorithm

Each client key owns a token bucket with a configured refill rate and burst
capacity. Requests consume one token; when the bucket is empty the gateway
returns HTTP 429 with a `Retry-After` header.

## Defaults

- Public API: 100 requests/second sustained, burst 200.
- Authenticated API: 1,000 requests/second sustained, burst 2,000.
- Bulk export endpoints: 5 requests/minute per tenant.

## Distributed state

Bucket state is stored in Redis with atomic Lua scripts. Clock skew is
bounded by using Redis server time rather than gateway local time. Rate-limit
decisions are emitted as metrics for capacity planning.

## Fairness

Tenant-level quotas prevent noisy neighbors. Per-user limits are applied
after tenant quotas so that a single tenant cannot exhaust shared capacity.
