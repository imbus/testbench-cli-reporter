---
sidebar_position: 1
title: TestBench 3.x vs 4.x
---

The CLI is built to work with both current TestBench 3.x installations and the upcoming TestBench 4.x API.

## Version detection

On startup, the client reads the server version from:

- `GET /api/2/serverVersions` (preferred)
- fallback: `GET /api/1/serverVersions`

The detected version influences authentication and which endpoints are used.

## Authentication

- TestBench 4.x: session-based authentication
  - the CLI requests a session token and sends it via the `Authorization` header
  - you can also supply an existing session token or a JWT via `--session`
  - for TestBench 4.x, the authentication is always done via the `/api/2/auth` endpoint, even if XML exports or other legacy endpoints are used
- TestBench 3.x: legacy authentication
  - the CLI uses HTTP basic auth to call legacy endpoints

## Feature availability

Some features depend on server capabilities:

- CSV export requires TestBench >= 3.0.6.2
- JSON export/import and JWT generation require TestBench 4.x+

