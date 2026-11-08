# Terraform State Management

Owner: Cloud Infrastructure

## Remote state

All Terraform state is stored in an encrypted S3 bucket with versioning
enabled. DynamoDB provides state locking. Local state files are prohibited.

## Workspace boundaries

Each production environment has a separate state root. Shared networking and
identity stacks are consumed through read-only remote state references.

## Change workflow

Plans run in CI and are posted to the pull request. Applies require approval
from the owning team. Destructive changes require a second reviewer from the
infrastructure guild.

## Drift detection

A scheduled job runs `terraform plan` against production every six hours.
Drift findings open a ticket with the owning service and block further applies
until resolved.
