# SRE SEV-1 Runbook

Owner: Site Reliability Engineering

## Severity definition

SEV-1 indicates a widespread outage or material data loss affecting multiple
customers. The incident commander declares SEV-1 and opens a dedicated
incident channel within five minutes.

## Immediate actions

1. Page the primary and secondary on-call.
2. Establish the incident bridge and assign roles: commander, communications,
   operations lead, and scribe.
3. Post an initial status update within 15 minutes.
4. Prefer mitigation over root-cause analysis. Roll back recent deploys first.

## Communications

Stakeholder updates are posted every 30 minutes until mitigation. Customer
communications are owned by Support and must be approved by the incident
commander.

## Post-incident

A blameless postmortem is due within five business days. Action items must
have owners and due dates, and are tracked to completion by the reliability
guild.
