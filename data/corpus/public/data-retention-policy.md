# Data Retention Policy

Owner: Data Governance

## Retention classes

Customer content is retained for 30 days after account deletion. Billing
records are retained for seven years. Application logs are retained for 90
days unless they are attached to an open incident.

## Deletion workflow

Deletion requests flow through the data governance service, which emits
tombstones to every registered data store. Stores must acknowledge completion
within 72 hours.

## Legal hold

Legal holds suspend deletion for named custodians and data classes. The legal
team owns hold release. Data governance audits hold coverage monthly.

## Backups

Backups follow the same retention class as their source data. Restores must
not reintroduce data that has already passed its retention deadline.
