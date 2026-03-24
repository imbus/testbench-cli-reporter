---
sidebar_position: 1
title: Authentication & connection
---

## Connection options

All subcommands accept the same connection options:

- `--server` TestBench server as `hostname`, `hostname:port`, or `https://host:port/api/`
- `--login` / `--password` credentials
- `--session` existing session token (or for JSON export or import, a JWT token)
- `--verify` verify TLS certificates

If you provide `hostname` without a port, the CLI assumes port `443` and always uses `https://.../api/`.

## When to use `--session`

`--session` is only used for TestBench 4.x, where the API issues a session token.

If you provide `--login` and `--password`, the CLI will:

- detect the TestBench server version
- authenticate using the appropriate mechanism for that version

## Config file authentication fields

In automatic mode configs, each entry in `configuration[]` can contain:

- `sessionToken`: a session token or JWT token (TestBench 4.x)
- `basicAuth`: base64 of `login:password`
- `loginname` / `password`: optional plaintext credentials

The CLI can also override these fields at runtime via `--login/--password` or `--session`.
