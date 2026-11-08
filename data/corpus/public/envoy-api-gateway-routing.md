# Envoy API Gateway Routing

Owner: Edge Platform

## Responsibilities

The Envoy edge gateway terminates TLS, performs authentication, applies
rate limits, and routes traffic to internal services. Route configuration is
generated from a declarative service catalog and deployed via xDS.

## Routing rules

Routes match on host, path prefix, and headers. Canary traffic is shifted
using weighted clusters with a maximum step of 5% per minute. All routes
must declare a retry budget and a circuit-breaker threshold.

## Identity vendor integration

The gateway delegates token validation to the configured identity provider.
Current integrations include an internal OIDC issuer and a third-party
identity vendor for workforce SSO. Vendor failover is handled by a secondary
issuer behind the same discovery endpoint.
