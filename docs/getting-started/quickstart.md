---
sidebar_position: 2
title: Quickstart
---

## 1) Manual mode (interactive)

Run without subcommands:

```bash
testbench-cli-reporter
```

You can pre-seed connection defaults:

```bash
testbench-cli-reporter --server localhost:443 --login tt-admin --password admin
```

## 2) Command mode (non-interactive)

All commands share the same connection options:

- `--server hostname[:port]` (or `https://host:port/api/`)
- `--login` / `--password` (or `--session`)
- `--verify` to enable TLS verification

Example: export an XML execution package

```bash
testbench-cli-reporter export-xml \
  --server localhost:443 \
  --login tt-admin --password admin \
  --tov-key 123456 --cycle-key 234567 \
  --uid itb-TT-8161 \
  --output report.zip
```

Example: import XML execution results

```bash
testbench-cli-reporter import-xml \
  --server localhost:443 \
  --login tt-admin --password admin \
  --input report.zip
```

## 3) Automatic mode (config file)

Run with `--config`:

```bash
testbench-cli-reporter --config path/to/config.json
```

See the configuration reference for details.
