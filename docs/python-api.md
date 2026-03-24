---
sidebar_position: 80
title: Python API
---

The `testbench-cli-reporter` package exposes a Python API so you can drive TestBench actions programmatically — for example from a CI script, a test framework plugin, or a custom orchestration tool.

## Installation

```bash
pip install testbench-cli-reporter
```

## Quick start

```python
from testbench_cli_reporter import (
    CliReporterConfig,
    Configuration,
    ExportXmlAction,
    ExportXmlParameters,
    TestCycleXMLReportOptions,
    run_automatic_mode,
)

export_config = TestCycleXMLReportOptions(
    exportAttachments=True,
    exportDesignData=True,
    reportRootUID="iTB-TT-1234567890",
    suppressFilteredData=True,
    characterEncoding="utf-16",
    exportExpandedData=True,
    filters=[],
    exportExecutionProtocols=False,
    exportDescriptionFields=True,
    outputFormattedText=True,
)

action = ExportXmlAction(
    parameters=ExportXmlParameters(
        outputPath="report.zip",
        tovKey="123456",
        cycleKey="234567",
        report_config=export_config,
    )
)

config = CliReporterConfig(
    configuration=[
        Configuration(
            server_url="https://localhost:443/api/",
            verify=False,
            actions=[action],
        )
    ]
)

run_automatic_mode(
    config,
    loginname="tt-admin",
    password="admin",
)
```

## `run_automatic_mode`

```python
def run_automatic_mode(
    configuration: CliReporterConfig | dict[str, Any],
    loginname: str | None = None,
    password: str | None = None,
    sessionToken: str | None = None,
    raise_exceptions: bool = False,
) -> None
```

Runs one or more actions against one or more TestBench servers.

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `configuration` | `CliReporterConfig` or `dict` | | The full configuration. If a `dict` is passed it is automatically converted to `CliReporterConfig` |
| `loginname` | `str \| None` | `None` | Override the login name in the configuration |
| `password` | `str \| None` | `None` | Override the password in the configuration |
| `sessionToken` | `str \| None` | `None` | Override the session token in the configuration |
| `raise_exceptions` | `bool` | `False` | When `True`, HTTP errors propagate as exceptions. When `False`, they are logged and execution continues |

### Behaviour

1. Converts `configuration` to `CliReporterConfig` if needed
2. Sets up logging from `configuration.loggingConfiguration`
3. Opens connections to all configured servers
4. Queues and executes all actions, respecting `thread_limit`
5. Polls until all jobs finish
6. On HTTP errors: logs the response JSON; re-raises if `raise_exceptions=True`

## Configuration objects

All configuration dataclasses can be imported directly from `testbench_cli_reporter`:

```python
from testbench_cli_reporter import (
    # Top-level config
    CliReporterConfig,
    Configuration,
    loggingConfig,

    # Actions
    ExportXmlAction,
    ExportJsonAction,
    ExportCsvAction,
    ExportServerLogsAction,
    ImportXMLAction,
    ImportJSONAction,
    RequestJWTAction,

    # Action parameters
    ExportXmlParameters,
    ExportJsonParameters,
    ExportCsvParameters,
    ExportServerLogsParameters,
    ImportXmlParameters,
    ImportJsonParameters,
    JWTDataOptions,

    # Supporting types
    FilteringOptions,
    Key,
    Permission,
    ProjectCSVReportOptions,
    ProjectCSVReportScope,
)
```

### `CliReporterConfig`

Top-level configuration container.

| Field | Type | Default | Description |
|---|---|---|---|
| `configuration` | `list[Configuration]` | `[]` | List of server connections |
| `loggingConfiguration` | `loggingConfig` | defaults | Console and file logging settings |

### `Configuration`

A single server connection with its actions.

| Field | Type | Default | Description |
|---|---|---|---|
| `server_url` | `str \| None` | `None` | Full server URL (`https://host:port/api/`) |
| `verify` | `bool` | `True` | Verify TLS certificates |
| `sessionToken` | `str \| None` | `None` | Session token |
| `basicAuth` | `str \| None` | `None` | Base64-encoded `login:password` |
| `loginname` | `str \| None` | `None` | Plaintext login name |
| `password` | `str \| None` | `None` | Plaintext password |
| `actions` | `list[BaseAction] \| None` | `None` | Actions to execute |
| `thread_limit` | `int \| None` | `None` | Max concurrent actions (`None` = unlimited) |

### `loggingConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `console.logLevel` | `LogLevel` | `INFO` | Console log level |
| `console.logFormat` | `str` | `"%(message)s"` | Console log format |
| `file.logLevel` | `LogLevel` | `DEBUG` | File log level |
| `file.fileName` | `str` | `"testbench-cli-reporter.log"` | Log file path |
| `file.logFormat` | `str` | `"%(asctime)s - ..."` | File log format |

## Examples

### Import XML results

```python
from testbench_cli_reporter import (
    CliReporterConfig,
    Configuration,
    ImportXMLAction,
    ImportXmlParameters,
    ExecutionXmlResultsImportOptions,
    run_automatic_mode,
)

import_config = ExecutionXmlResultsImportOptions(
    fileName="",
    reportRootUID=None,
    ignoreNonExecutedTestCases=True,
    defaultTester=None,
    checkPaths=True,
    filters=None,
    discardTesterInformation=True,
    useExistingDefect=True,
)

action = ImportXMLAction(
    parameters=ImportXmlParameters(
        inputPath="results.zip",
        importConfig=import_config,
    )
)

config = CliReporterConfig(
    configuration=[
        Configuration(
            server_url="https://testbench.example.com:443/api/",
            verify=True,
            actions=[action],
        )
    ]
)

run_automatic_mode(config, loginname="ci-user", password="secret")
```

### Export JSON report

```python
from testbench_cli_reporter import (
    CliReporterConfig,
    Configuration,
    ExportJsonAction,
    ExportJsonParameters,
    TestCycleJsonReportOptions,
    run_automatic_mode,
)

report_config = TestCycleJsonReportOptions(
    treeRootUID=None,
    basedOnExecution=True,
    suppressFilteredData=True,
    suppressNotExecutable=True,
    suppressEmptyTestThemes=True,
    executionMode="EXECUTE",
    filters=[],
)

action = ExportJsonAction(
    parameters=ExportJsonParameters(
        outputPath="json-report.zip",
        projectKey="111",
        tovKey="222",
        cycleKey="333",
        report_config=report_config,
    )
)

config = CliReporterConfig(
    configuration=[
        Configuration(
            server_url="https://localhost:443/api/",
            verify=False,
            actions=[action],
        )
    ]
)

run_automatic_mode(config, loginname="tt-admin", password="admin")
```

### Generate a JWT

```python
from testbench_cli_reporter import (
    CliReporterConfig,
    Configuration,
    JWTDataOptions,
    Permission,
    RequestJWTAction,
    run_automatic_mode,
)

action = RequestJWTAction(
    parameters=JWTDataOptions(
        projectKey="111",
        permissions=[
            Permission.ReadProjectHierarchy,
            Permission.ImportExecutionResults,
        ],
        subject="my-service",
        expiresAfterSeconds=3600,
    )
)

config = CliReporterConfig(
    configuration=[
        Configuration(
            server_url="https://localhost:443/api/",
            verify=False,
            actions=[action],
        )
    ]
)

run_automatic_mode(config, loginname="tt-admin", password="admin")
```

### Using a dict instead of dataclasses

You can also pass a plain dictionary matching the JSON config file schema:

```python
from testbench_cli_reporter import run_automatic_mode

run_automatic_mode(
  {
    "configuration": [
      {
        "server_url": "https://localhost:443/api/",
        "verify": False,
        "actions": [
          {
            "type": "ExportXMLReport",
            "parameters": {
              "outputPath": "report.zip",
              "tovKey": "123456",
              "cycleKey": "234567",
              "report_config": {
                "exportAttachments": True,
                "exportDesignData": True,
                "characterEncoding": "utf-16",
                "suppressFilteredData": True,
                "exportExpandedData": True,
                "exportDescriptionFields": True,
                "outputFormattedText": False,
                "exportExecutionProtocols": False,
                "filters": [],
                "reportRootUID": None,
              },
            },
          }
        ],
      }
    ]
  },
  loginname="tt-admin",
  password="admin",
)
```

### Error handling

Set `raise_exceptions=True` for CI pipelines where you want failures to stop the build:

```python
try:
    run_automatic_mode(config, loginname="ci-user", password="secret", raise_exceptions=True)
except Exception as e:
    print(f"TestBench action failed: {e}")
    sys.exit(1)
```
