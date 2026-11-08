# Postgres Zero-Downtime Migrations

Owner: Database Reliability

## Principles

Schema changes are applied in expand/contract phases. The expand phase adds
new nullable columns, backfills asynchronously, and dual-writes. The contract
phase removes legacy columns only after all readers have migrated.

## Safe operations

- Adding a nullable column without a default is safe.
- Adding an index requires `CONCURRENTLY` and must run outside a transaction.
- Backfills are batched at 1,000 rows with sleep between batches.

## Unsafe operations

`ALTER TABLE ... SET NOT NULL` without a validated constraint, table
rewrites, and exclusive locks on hot tables are prohibited during business
hours. Use the migration linter in CI to block unsafe statements.

## Rollback

Every migration must include a forward-fix plan. Destructive rollbacks are
not permitted in production; prefer feature flags to disable new code paths.
