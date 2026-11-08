# Auth v2 Specification

Status: Draft for engineering review
Owner: Identity Platform

## Overview

Auth v2 replaces the legacy shared-secret session layer with short-lived,
asymmetric access tokens. Access tokens are Ed25519-signed JWTs with a
15-minute lifetime. Refresh tokens are opaque, rotated on every use, and
bound to a device fingerprint.

## Token lifecycle

1. The client authenticates against `/oauth/token` using PKCE.
2. The authorization service issues an access token and a rotating refresh token.
3. Access tokens are validated locally by services using the published JWKS.
4. Refresh token reuse invalidates the entire token family and forces re-authentication.

## Scopes and claims

Tokens carry `sub`, `groups`, `scope`, and `tenant_id` claims. Downstream
services MUST authorize on `scope` and MUST NOT trust client-supplied group
claims without verifying the token signature.

## Migration notes

The legacy `/session` endpoint will remain available until 2026-Q2. Clients
should migrate to the PKCE flow before the deprecation deadline.
