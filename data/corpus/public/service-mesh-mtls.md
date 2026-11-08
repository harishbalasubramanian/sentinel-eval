# Service Mesh mTLS

Owner: Security Engineering

## Identity

Workloads receive SPIFFE identities from the mesh control plane. Certificates
rotate every 24 hours and are scoped to the Kubernetes service account.

## Transport policy

All service-to-service traffic uses mutual TLS. Plaintext connections are
rejected at the sidecar. Egress to external services uses a dedicated gateway
with an explicit allowlist.

## Authorization

Mesh authorization policies default to deny. Service owners declare allowed
callers by identity and HTTP method. Policy changes are reviewed by the
security guild.

## Key handling

Private keys never leave the workload node. The control plane cannot decrypt
application traffic. Certificate requests are audited and retained for one
year.
