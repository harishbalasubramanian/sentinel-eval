# AWS VPC Setup

Owner: Cloud Infrastructure

## Network layout

The production VPC uses `10.40.0.0/16` with three private application subnets
and three public edge subnets across separate availability zones. Database
subnets are isolated and have no route to the internet gateway.

## Egress and endpoints

Private workloads reach external dependencies through NAT gateways. S3 and
STS traffic uses VPC endpoints to avoid NAT data charges. Endpoint policies
are scoped to the owning account and required bucket prefixes.

## Peering

Shared services peer with the production VPC over a transit gateway. Route
tables are generated from the service catalog and reviewed by the network
guild before deployment.

## Change control

Security group changes require a pull request and automated diff review.
Ingress rules must declare a owning service and a business justification.
