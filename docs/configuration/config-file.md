---
sidebar_position: 1
title: Config file (automatic mode)
---

Automatic mode reads a JSON config. Top-level schema:

- `configuration`: list of server connections
- `loggingConfiguration` (optional): console/file logging setup (see [Logging](./logging.md))

## Connection fields

Each entry under `configuration[]` supports these fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `server_url` | string | | Full server URL (e.g. `https://localhost:443/api/`) |
| `verify` | boolean | `true` | Verify TLS certificates |
| `sessionToken` | string | | Session token (TestBench 4.x) |
| `basicAuth` | string | | Base64-encoded `login:password` |
| `loginname` | string | | Plaintext login name |
| `password` | string | | Plaintext password |
| `actions` | array | `[]` | List of actions to execute |
| `thread_limit` | integer | | Max concurrent actions per connection (`null`/omitted = unlimited) |

## Minimal example

```json
{
  "configuration": [
    {
      "server_url": "https://localhost:443/api/",
      "verify": false,
      "loginname": "tt-admin",
      "password": "admin",
      "actions": []
    }
  ]
}
```

## Actions

Each entry under `actions[]` has:

- `type`: the action type string
- `parameters`: action-specific payload

Available action types:

| `type` | Description |
|---|---|
| `ExportXMLReport` | Export an XML execution package |
| `ImportXMLExecutionResults` | Import XML execution results |
| `ExportJSONReport` | Export a JSON execution package |
| `ImportJSONExecutionResults` | Import JSON execution results |
| `ExportCSVReport` | Export a CSV report |
| `ExportServerLogs` | Export server logs |
| `RequestJWT` | Generate a JWT token |

---

## Action parameters reference

### `ExportXMLReport`

```json
{
  "type": "ExportXMLReport",
  "parameters": {
    "outputPath": "report.zip",
    "projectPath": ["My Project", "Version 1.0", "Cycle 1"],
    "tovKey": "123456",
    "cycleKey": "234567",
    "report_config": {
      "exportAttachments": true,
      "exportDesignData": true,
      "characterEncoding": "utf-16",
      "suppressFilteredData": true,
      "exportExpandedData": true,
      "exportDescriptionFields": true,
      "outputFormattedText": false,
      "exportExecutionProtocols": false,
      "filters": [],
      "reportRootUID": "itb-TT-8161"
    }
  }
}
```

| Parameter | Type | Description |
|---|---|---|
| `outputPath` | string | Output zip file path |
| `projectPath` | string[] | `[project, version]` or `[project, version, cycle]` (by name) |
| `tovKey` | string | Test object version key (alternative to `projectPath`) |
| `cycleKey` | string | Test cycle key |
| `report_config` | object | Export options (see below) |

**`report_config` fields:**

| Field | Type | Description |
|---|---|---|
| `exportAttachments` | boolean | Include attachments |
| `exportDesignData` | boolean | Include design data |
| `characterEncoding` | string | `"utf-8"` or `"utf-16"` |
| `suppressFilteredData` | boolean | Exclude filtered data |
| `exportExpandedData` | boolean | Include expanded data |
| `exportDescriptionFields` | boolean | Include description fields |
| `outputFormattedText` | boolean | Output formatted text |
| `exportExecutionProtocols` | boolean | Include execution protocols |
| `filters` | array | List of `FilterInfo` objects |
| `reportRootUID` | string | Root UID for the report tree |

### `ImportXMLExecutionResults`

```json
{
  "type": "ImportXMLExecutionResults",
  "parameters": {
    "inputPath": "report.zip",
    "projectPath": ["My Project", "Version 1.0", "Cycle 1"],
    "importConfig": {
      "fileName": "",
      "reportRootUID": null,
      "ignoreNonExecutedTestCases": true,
      "defaultTester": null,
      "checkPaths": true,
      "filters": null,
      "discardTesterInformation": true,
      "useExistingDefect": true
    }
  }
}
```

| Parameter | Type | Description |
|---|---|---|
| `inputPath` | string | Path to the XML results zip file |
| `projectPath` | string[] | `[project, version, cycle]` (by name) |
| `cycleKey` | string | Test cycle key (alternative to `projectPath`) |
| `importConfig` | object | Import options (see below) |

**`importConfig` fields:**

| Field | Type | Description |
|---|---|---|
| `fileName` | string | File name within the zip (usually left empty) |
| `reportRootUID` | string | Report root UID |
| `ignoreNonExecutedTestCases` | boolean | Skip non-executed test cases |
| `defaultTester` | string | Default tester login name |
| `checkPaths` | boolean | Validate paths during import |
| `filters` | array | List of `FilterInfo` objects |
| `discardTesterInformation` | boolean | Discard tester information from the import |
| `useExistingDefect` | boolean | Reuse existing defects |

### `ExportJSONReport`

```json
{
  "type": "ExportJSONReport",
  "parameters": {
    "outputPath": "json-report.zip",
    "projectPath": ["My Project", "Version 1.0", "Cycle 1"],
    "projectKey": "111",
    "tovKey": "222",
    "cycleKey": "333",
    "report_config": {
      "treeRootUID": null,
      "basedOnExecution": true,
      "suppressFilteredData": true,
      "suppressNotExecutable": true,
      "suppressEmptyTestThemes": true,
      "executionMode": "EXECUTE",
      "filters": []
    }
  }
}
```

| Parameter | Type | Description |
|---|---|---|
| `outputPath` | string | Output zip file path |
| `projectPath` | string[] | `[project, version]` or `[project, version, cycle]` (by name) |
| `projectKey` | string | Project key (alternative to `projectPath`) |
| `tovKey` | string | Test object version key |
| `cycleKey` | string | Test cycle key |
| `report_config` | object | Export options (see below) |

**`report_config` fields:**

| Field | Type | Description |
|---|---|---|
| `treeRootUID` | string | Root UID for the tree |
| `basedOnExecution` | boolean | Base report on execution data |
| `suppressFilteredData` | boolean | Exclude filtered data |
| `suppressNotExecutable` | boolean | Exclude non-executable items |
| `suppressEmptyTestThemes` | boolean | Exclude empty test themes |
| `executionMode` | string | One of: `EXECUTE`, `CONTINUE`, `VIEW`, `SIMULATE` |
| `filters` | array | List of `FilterInfo` objects |

### `ImportJSONExecutionResults`

```json
{
  "type": "ImportJSONExecutionResults",
  "parameters": {
    "inputPath": "json-report.zip",
    "projectKey": "111",
    "cycleKey": "333",
    "importConfig": {
      "fileName": "",
      "treeRootUID": null,
      "useExistingDefect": true,
      "ignoreNonExecutedTestCases": true,
      "checkPaths": true,
      "filters": null,
      "discardTesterInformation": true,
      "defaultTester": null
    }
  }
}
```

| Parameter | Type | Description |
|---|---|---|
| `inputPath` | string | Path to the JSON results zip file |
| `projectKey` | string | Project key |
| `cycleKey` | string | Test cycle key |
| `projectPath` | string[] | `[project, version, cycle]` (by name, alternative to keys) |
| `importConfig` | object | Import options (same fields as XML import, plus `treeRootUID` instead of `reportRootUID`) |

### `ExportCSVReport`

```json
{
  "type": "ExportCSVReport",
  "parameters": {
    "outputPath": "csv_report.zip",
    "projectKey": "111",
    "report_config": {
      "scopes": [
        {
          "tovKey": { "serial": "222" },
          "reportRootUID": null,
          "cycleKeys": [{ "serial": "333" }]
        }
      ],
      "showUserFullName": true,
      "characterEncoding": "utf-8",
      "fields": ["spec.name", "spec.status", "exec.verdict"]
    }
  }
}
```

| Parameter | Type | Description |
|---|---|---|
| `outputPath` | string | Output zip file path |
| `projectKey` | string | Project key |
| `report_config` | object | CSV report options (see below) |

**`report_config` fields:**

| Field | Type | Description |
|---|---|---|
| `scopes` | array | List of report scopes (TOV key + optional cycle keys) |
| `showUserFullName` | boolean | Show full user names in the CSV |
| `characterEncoding` | string | `"utf-8"`, `"utf-16"`, or `"windows-1252"` |
| `fields` | string[] | CSV fields to include (e.g. `spec.name`, `exec.verdict`, `aut.status`) |

### `ExportServerLogs`

```json
{
  "type": "ExportServerLogs",
  "parameters": {
    "outputPath": "server_logs.zip"
  }
}
```

| Parameter | Type | Description |
|---|---|---|
| `outputPath` | string | Output zip file path |

### `RequestJWT`

```json
{
  "type": "RequestJWT",
  "parameters": {
    "projectKey": "111",
    "tovKey": "222",
    "cycleKey": "333",
    "permissions": ["ReadProjectHierarchy", "ImportExecutionResults"],
    "subject": "my-service",
    "expiresAfterSeconds": 3600
  }
}
```

| Parameter | Type | Description |
|---|---|---|
| `projectKey` | string | Project key |
| `tovKey` | string | Test object version key |
| `cycleKey` | string | Test cycle key |
| `permissions` | string[] | List of permission names |
| `subject` | string | Subject claim for the token |
| `expiresAfterSeconds` | integer | Token expiry in seconds |

---

## `thread_limit`

`thread_limit` limits the number of concurrent actions per connection.

- omitted / `null`: no limit
- `0` or negative values are treated as unlimited

## Full example with multiple actions

```json
{
  "configuration": [
    {
      "server_url": "https://testbench.example.com:443/api/",
      "verify": true,
      "basicAuth": "dHQtYWRtaW46YWRtaW4=",
      "thread_limit": 2,
      "actions": [
        {
          "type": "ExportXMLReport",
          "parameters": {
            "outputPath": "export1.zip",
            "tovKey": "123456",
            "cycleKey": "234567",
            "report_config": {
              "exportAttachments": true,
              "exportDesignData": true,
              "characterEncoding": "utf-16",
              "suppressFilteredData": true,
              "exportExpandedData": true,
              "exportDescriptionFields": true,
              "outputFormattedText": false,
              "exportExecutionProtocols": false,
              "filters": [],
              "reportRootUID": null
            }
          }
        },
        {
          "type": "ImportXMLExecutionResults",
          "parameters": {
            "inputPath": "results.zip",
            "importConfig": {
              "fileName": "",
              "reportRootUID": null,
              "ignoreNonExecutedTestCases": true,
              "defaultTester": null,
              "checkPaths": true,
              "filters": null,
              "discardTesterInformation": true,
              "useExistingDefect": true
            }
          }
        }
      ]
    }
  ],
  "loggingConfiguration": {
    "console": { "logLevel": "INFO" },
    "file": { "logLevel": "DEBUG", "fileName": "run.log" }
  }
}
```
