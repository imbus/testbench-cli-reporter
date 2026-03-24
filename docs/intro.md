---
sidebar_position: 1
title: Introduction
---

TestBench CLI Reporter is a Python CLI that automates common TestBench API workflows:

- Export reports (XML/JSON) for automated test runs or documentation purposes
- Import execution results back from automated test runs or iTorx executions into TestBench
- Export CSV reports (availability depends on TestBench version 4.x)
- Administrator helpers like server log export and JWT creation

It supports three usage modes:

- **Manual mode** — interactive prompts and menus
- **Command mode** — non-interactive subcommands (e.g. `export-xml`, `import-json`)
- **Automatic mode** — config-file-driven batch execution

It can also be used as a **Python library** via the `run_automatic_mode` API.

The CLI is designed to work with **TestBench 3.x** and the upcoming **TestBench 4.x** API.

## Quick start

Interactive (manual) mode:

```powershell
testbench-cli-reporter
```

Command mode example:

```powershell
testbench-cli-reporter export-xml \
  --server localhost:443 \
  --login tt-admin --password admin \
  --cycle-key 234567 \
  --uid itb-TT-8161 \
  --output report.zip
```

Automatic mode (config file):

```powershell
testbench-cli-reporter --config path/to/config.json
```

Python API:

```python
from testbench_cli_reporter import run_automatic_mode, CliReporterConfig, ...

run_automatic_mode(config, loginname="tt-admin", password="admin")
```

See the [Python API reference](python-api) for details.

## Server URL format

Every command that talks to TestBench accepts `--server` as either:

- `hostname` (defaults to port `443`)
- `hostname:port`
- full URL like `https://hostname:port/api/`

The CLI always normalizes the server value to `https://.../api/`.

## TLS certificate verification

- By default, command mode does **not** verify TLS certificates.
- Add `--verify` to enable certificate verification.
- In config files, `verify` defaults to `true` when omitted.

## License

TestBench CLI Reporter is fully Open-Source licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).