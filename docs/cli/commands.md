---
sidebar_position: 2
title: Commands
---

This section documents the explicit, non-interactive subcommands.

All commands require a connection via `--server` and either `--session` or `--login`/`--password`.


## Project Path or Keys

Many commands that operate on a project, test object version, or test cycle accept either:
- The name of the project, version, or cycle<br />
  (e.g. `--project "My Project" --version "Release 1.0" --cycle "Cycle A"`)
- The key of the project, version, or cycle<br />
  (e.g. `--project-key 102 --tov-key 1223 --cycle-key 5121`)

If the keys are provided, they take precedence over the names.
If no keys are provided, the CLI Reporter tries to resolve the names to keys by querying the TestBench server.


## Common connection options

Every subcommand accepts these options:

| Option | Short | Description |
|---|---|---|
| `--server` | `-s` | TestBench server address (`hostname[:port]` or full URL) |
| `--login` | | Login name for authentication |
| `--password` | | Password for authentication |
| `--session` | | Existing session token (alternative to login/password) |
| `--verify` | | Enable TLS certificate verification (flag, off by default) |

These options can also be set on the main `testbench-cli-reporter` command and inherited by subcommands.

---

## `export-xml`

Export an XML full report (zip).

```bash
testbench-cli-reporter export-xml -s HOST[:PORT] --login USER --password PASS \
  --tov-key TOV --cycle-key CYCLE --uid itb-TT-1234 -o report.zip
```

| Option | Short | Required | Default | Description |
|---|---|---|---|---|
| `--project` | `-p` | | | Project name |
| `--version` | `-v` | | | Test object version name |
| `--cycle` | `-y` | | | Test cycle name |
| `--project-key` | | | | Project key (currently not relevant for XML export) |
| `--tov-key` | | | | Test object version key |
| `--cycle-key` | | | | Test cycle key |
| `--uid` | `-u` | | | Report root UID (test theme root). If omitted, exports the full tree |
| `--filtering` | | | | FilteringOptions payload as base64-encoded JSON (see [FilteringOptions](../configuration/filtering-options.md)) |
| `--output` | `-o` | | `report.zip` | Output zip file path |

You must provide either `--project`/`--version`[/`--cycle`] (by name) or `--tov-key`/`--cycle-key` (by key).

---

## `import-xml`

Import an XML execution results zip back into TestBench.

Project, version, and cycle are determined from the XML content and don't need to be provided as options.

```bash
testbench-cli-reporter import-xml -s HOST[:PORT] --login USER --password PASS \
  --input report.zip
```

| Option | Short | Required | Default | Description |
|---|---|---|---|---|
| `--input` | `-i` | **yes** | | Path to the XML results zip file |
| `--uid` | `-u` | | `ROOT` | Report root UID |
| `--filtering` | | | | FilteringOptions payload as base64-encoded JSON |

---

## `export-json`

Export a JSON full report (zip).

```bash
testbench-cli-reporter export-json -s HOST[:PORT] --login USER --password PASS \
  --project-key PROJECT --tov-key TOV --cycle-key CYCLE \
  --uid itb-TT-1234 -o json-report.zip
```

| Option | Short | Required | Default | Description |
|---|---|---|---|---|
| `--project` | `-p` | | | Project name |
| `--version` | `-v` | | | Test object version name |
| `--cycle` | `-y` | | | Test cycle name |
| `--project-key` | | | | Project key |
| `--tov-key` | | | | Test object version key |
| `--cycle-key` | | | | Test cycle key |
| `--uid` | `-u` | | | Tree root UID |
| `--filtering` | | | | FilteringOptions payload as base64-encoded JSON |
| `--output` | `-o` | | `json-report.zip` | Output zip file path |

You must either provide the keys for project and tov or cylce, or the names for project and version (and optionally cycle).

---

## `import-json`

Import a JSON execution results zip back into TestBench.

Project, test object version, and test cycle are determined from the JSON report metadata.

```bash
testbench-cli-reporter import-json -s HOST[:PORT] --login USER --password PASS \
  --input json-report.zip
```

| Option | Short | Required | Default | Description |
|---|---|---|---|---|
| `--input` | `-i` | **yes** | | Path to the JSON results zip file |
| `--uid` | `-u` | | | Report root UID |
| `--filtering` | | | | FilteringOptions payload as base64-encoded JSON |

---

## `export-csv`

Export a CSV report zip.

```bash
testbench-cli-reporter export-csv -s HOST[:PORT] --login USER --password PASS \
  --project-key PROJECT --tov-key TOV --cycle-key CYCLE --cycle-key CYCLE2 \
  --uid itb-TT-1234 -o csv_report.zip
```

| Option | Short | Required | Default | Description |
|---|---|---|---|---|
| `--project-key` | | **yes** | | Project key |
| `--tov-key` | | **yes** | | Test object version key |
| `--cycle-key` | | | | Test cycle key (repeatable; omit to export without cycle scope) |
| `--uid` | `-u` | | | Report root UID |
| `--output` | `-o` | | `csv_report.zip` | Output zip file path |

---

## `export-logs`

Administrator helper: export TestBench server logs as a zip.

```bash
testbench-cli-reporter export-logs -s HOST[:PORT] --login USER --password PASS \
  -o server_logs.zip
```

| Option | Short | Required | Default | Description |
|---|---|---|---|---|
| `--output` | `-o` | | `server_logs.zip` | Output zip file path |

---

## `gen-jwt`

Generate a JWT based on the current session (TestBench 4.x+).

```bash
testbench-cli-reporter gen-jwt -s HOST[:PORT] --login USER --password PASS \
  --permission ReadProjectHierarchy --permission ImportExecutionResults \
  --project-key PROJECT --tov-key TOV --cycle-key CYCLE \
  --subject my-service --expires 3600
```

| Option | Short | Required | Default | Description |
|---|---|---|---|---|
| `--permission` | | | | Permission to include (repeatable; accepts comma or `\|` separated lists) |
| `--project-key` | | | | Project key |
| `--tov-key` | | | | Test object version key |
| `--cycle-key` | | | | Test cycle key |
| `--subject` | | | | Subject claim for the token |
| `--expires` | | | | Token expiry in seconds |

Run `testbench-cli-reporter gen-jwt --help` to see the full list of available permission names.
