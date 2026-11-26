# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`testbench-cli-reporter` is a CLI (and importable Python library) that talks to the REST API of an
imbus **TestBench** server: it exports XML/JSON/CSV reports and imports automated test execution
results back into TestBench. Typical use is a CI/CD pipeline running e.g. RobotFramework tests and
pushing the results back.

## Commands

```bash
pip install -e ".[dev,test]"        # dev setup (flit backend, needs Python >= 3.10)
pre-commit install                  # wires up mypy, ruff, robocop

ruff format . && ruff check .       # format + lint (line-length 110, target py310)
mypy src                            # type check (config in pyproject.toml)
pre-commit run --all-files          # everything the hooks run

testbench-cli-reporter --help       # run the CLI (alias: TestBenchCliReporter)
python -m testbench_cli_reporter    # same, without installing scripts
python start.py                     # thin wrapper used for local runs
```

### Tests

Tests are **RobotFramework acceptance tests** that drive the installed CLI as a subprocess. They
require a *live TestBench server* reachable at `localhost:443` with the credentials in
`tests/resources/Keywords.robot` (`tt-admin` / `admin`) — there is no mock server and no unit-test
suite, so they cannot run in a plain checkout.

```bash
robot tests/tests                                 # whole suite
robot tests/tests/test_xml_export.robot           # single suite
robot --test "Should Display Authenticated Message If Valid Credentials" tests/tests   # single test
robocop check tests && robocop format tests       # lint/format the .robot files
```

Caveat: parts of `tests/` still target the pre-3.0 argparse CLI (they pass `--tovKey`, `--type` and
assert on `usage:` / `positional arguments:` / `unrecognized arguments`). The 3.0 CLI is Click-based
with subcommands and different flag spellings, so failures there are likely stale tests rather than
regressions — check `src/testbench_cli_reporter/__main__.py` before "fixing" the code.

### Release

Version lives in exactly one place: `__version__` in `src/testbench_cli_reporter/__init__.py`
(flit reads it; `pyproject.toml` declares it `dynamic`). `setup.py` is vestigial — it still points at
the old `src/TestBenchCliReporter/` path and is not used by the build. Publishing a GitHub Release
triggers `.github/workflows/release-binaries.yml`, which builds the wheel with flit and PyInstaller
one-file binaries for linux/macos/windows from `pyinstaller/run.py`.

## Architecture

Everything lives in `src/testbench_cli_reporter/`. Data flows: CLI/config → `Configuration` objects →
`Connection` per server → `AbstractAction` lifecycle driven by an execution loop.

### Three run modes, one action pipeline

- **Command mode** — `__main__.py` Click subcommands (`export-xml`, `import-xml`, `export-json`,
  `import-json`, `export-csv`, `export-logs`, `gen-jwt`). Each one builds a single action + a
  synthetic `CliReporterConfig` in memory and hands it to `run_automatic_mode`.
- **Automatic mode** — `-c/--config <json>` → `util.get_configuration` → `CliReporterConfig.from_dict`
  → `execution.run_automatic_mode`. No prompts; `prepare()` is skipped.
- **Manual mode** — no config / `--manual` → `execution.run_manual_mode`, an interactive
  questionary menu loop (`questions.py`) that calls `prepare()` to fill parameters, then runs the same
  trigger/wait/finish steps.

### The two parallel action registries (important)

Action names like `"ExportXMLReport"` exist twice and must stay in sync:

- `config_model.ACTION_TYPES` → **declarative dataclasses** (`ExportXmlAction`, `ExportXmlParameters`, …)
  used for parsing/serializing config JSON and as the public Python API surface.
- `actions.ACTION_CLASSES` → **runtime implementations** (`ExportXMLReport`, …) subclassing
  `util.AbstractAction`. `actions.Action(name, params)` is the factory; `AbstractAction.export()` maps
  back to the dataclass so a session can be dumped as a config file.

Adding an action means: dataclass + parameters in `config_model.py`, entry in `ACTION_TYPES`, re-export
in `__init__.py.__all__`, implementation in `actions.py`, entry in `ACTION_CLASSES`, a menu `Choice` in
`questions.ask_for_main_action`/`ask_for_admin_action`, and usually a Click subcommand in `__main__.py`.

### Action lifecycle

`prepare()` (interactive only) → `trigger()` (start a server-side job, store `job_id`) →
`wait()` (manual mode, blocking) / `poll()` (automatic mode, non-blocking) → `finish()` (download and
write the output file). Automatic mode never blocks on one job: `execution.py` keeps per-connection
queues (`actions_to_trigger` / `actions_to_wait_for` / `actions_to_finish`), round-robins connections
via `ConnectionLog.next()` and `util.rotate`, and respects `thread_limit` per connection.

### Server communication — `testbench.py`

`Connection` wraps two `requests.Session`s and this is the main source of subtlety:

- **Version detection** drives everything: `server_version` from `/api/2/serverVersions` (falling back
  to `/api/1/`), exposed as `is_testbench_4`. Feature gating: JSON export/import and JWT need TB 4.x,
  CSV export needs >= 3.0.6.2 (see `questions.ask_for_main_action`).
- **Dual endpoints**: TB 4.x authenticates once via `/api/2/auth` and reuses that session token, but
  XML reports and several other calls still go to the *legacy* `/api/1/` service on a different port
  discovered at runtime (`server_legacy_port` → `legacy_session`). TB 3.x uses HTTP basic auth against
  the legacy endpoints only.
- A background **heartbeat thread** keeps the session alive; when the server kills the session it sets
  `session_terminated`, and manual mode offers re-login (`execution._handle_session_terminated`).
- `resolve_server_name` (in `util.py`) normalizes `host`, `host:port` and full URLs to
  `https://host:port/api/`; `Connection.__init__` rejects anything else.

### Config & CLI conventions

- `config_model.py` is hand-rolled dataclasses with explicit `from_dict` classmethods (no pydantic).
  Field names deliberately keep the server's camelCase (`tovKey`, `cycleKey`, `reportRootUID`) — ruff's
  `N815`/`N803` are disabled for this reason. Don't rename them; they are wire format *and* public API.
- Default report/import presets are module-level constants in `util.py`: `ITEP_EXPORT_CONFIG`,
  `TYPICAL_XML_IMPORT_CONFIG`, `TYPICAL_JSON_IMPORT_CONFIG`, and the `JsonExportConfig` mapping. The
  latter is a `CopyOnAccessDict` (deep-copies on `__getitem__`) so callers can mutate presets safely —
  elsewhere `deepcopy` is applied explicitly in `__main__.py`.
- `--filtering` on the CLI takes a base64-encoded `FilteringOptions` JSON blob
  (`util.load_filtering_options`, accepts standard and urlsafe base64).
- Global CLI defaults `--project/--version/--cycle` are stashed in `util._CLI_DEFAULTS` via
  `set_cli_defaults` and read back by interactive prompts — a deliberate module-level side channel.
- Command mode defaults to **no** TLS verification (`--verify` opts in); config files default
  `verify: true`.
- Logging goes through the single `log.logger` (a standalone `logging.Logger`, not the root logger)
  configured once by `setup_logger`; a rotating file handler writes `testbench-cli-reporter.log`.

## Docs

`docs/` is the source for the published Docusaurus site
(<https://imbus.github.io/testbench-ecosystem-documentation/testbench-cli-reporter/intro>) — files carry
frontmatter with `sidebar_position`. `docs/python-api.md` and `docs/configuration/config-file.md`
document the dataclass/JSON surface, so keep them in step with `config_model.py`.
`.github/workflows/trigger-docs-release.yml` pushes doc changes to the documentation repo.
