---
sidebar_position: 2
title: Automatic mode
---

Automatic mode runs one or more actions from a JSON config file.
Such a config file can be generated from the manual mode history (see [Manual mode](manual-mode.md#writing-history-to-config-file)) or written by hand.

:::tip

   The easiest way to get a config file is to run some actions in manual mode and then export the history to a config file.

:::


```bash title="Run automatic mode with a config file"
testbench-cli-reporter --config path/to/config.json
```

## How it works

- Each config entry under `configuration[]` creates one connection.
- Each connection processes its queued `actions[]`.
- Jobs are executed concurrently per connection when you set `thread_limit`.

## Overriding credentials

You can override credentials provided in the config by passing CLI options:

- `--login` / `--password`
- `--session`

These override values in `configuration[]` at runtime.

## Failure handling

HTTP failures from TestBench propagate as `requests.HTTPError`.

- In normal CLI usage they are logged (including JSON payloads when available).
- In tests or programmatic usage, `raise_exceptions=True` is used to fail fast.

## Using automatic mode from Python

The same engine that powers `--config` is available as a Python API via `run_automatic_mode`.
See the [Python API reference](../python-api) for details.
