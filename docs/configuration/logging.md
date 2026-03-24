---
sidebar_position: 3
title: Logging
---

Logging can be configured via `loggingConfiguration` in the config file.

## Defaults

- Console logging defaults to `INFO` with a simple `%(message)s` format.
- File logging defaults to `DEBUG` in `testbench-cli-reporter.log`.

## Example

```json
{
  "configuration": [],
  "loggingConfiguration": {
    "console": {
      "logLevel": "INFO",
      "logFormat": "%(message)s"
    },
    "file": {
      "logLevel": "DEBUG",
      "fileName": "testbench-cli-reporter.log"
    }
  }
}
```
